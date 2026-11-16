#!/usr/bin/env python3
"""HackerOne loader: merges the hexbrain mirror (H1 report JSON + reddelexc data.csv) and the
ajaysenr/HackerOne-Disclosed-Reports archive into normalized/hackerone.jsonl (see SCHEMA.md).
Field priority: H1 JSON, then ajaysenr, then data.csv."""
import csv, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIRROR = Path("/home/cole/SiteResearch/hexbrain/mirror")
AJ = ROOT / "sources/hackerone/ajaysenr"
OUT = ROOT / "normalized/hackerone.jsonl"

# HackerOne weakness names that are not CWE names, mapped to the CWE HackerOne's taxonomy uses.
H1_CWE = {
    "information disclosure": 200, "improper access control - generic": 284,
    "improper authentication - generic": 287, "cross-site scripting (xss) - generic": 79,
    "cross-site scripting (xss) - reflected": 79, "cross-site scripting (xss) - stored": 79,
    "cross-site scripting (xss) - dom": 79, "cross-site scripting (xss)": 79, "reflected xss": 79,
    "business logic errors": 840, "cross-site request forgery (csrf)": 352,
    "insecure direct object reference (idor)": 639, "code injection": 94, "open redirect": 601,
    "server-side request forgery (ssrf)": 918, "server side request forgery": 918, "path traversal": 22,
    "memory corruption - generic": 119, "sql injection": 89, "blind sql injection": 89,
    "command injection - generic": 77, "os command injection": 78, "cryptographic issues - generic": 310,
    "improper restriction of authentication attempts": 307, "brute force": 307,
    "ui redressing (clickjacking)": 1021, "crlf injection": 93, "privacy violation": 359,
    "http request smuggling": 444, "classic buffer overflow": 120, "heap overflow": 122,
    "stack overflow": 121, "information exposure through sent data": 201, "resource injection": 99,
    "integer overflow": 190, "integer underflow": 191, "information exposure through directory listing": 548,
    "insufficient session expiration": 613, "information exposure through an error message": 209,
    "information exposure through debug information": 215,
    "improper neutralization of script-related html tags in a web page (basic xss)": 80,
    "man-in-the-middle": 300, "xml external entities (xxe)": 611, "xml entity expansion": 776,
    "concurrent execution using shared resource with improper synchronization ('race condition')": 362,
    "leveraging race conditions": 362, "http response splitting": 113, "array index underflow": 129,
    "remote file inclusion": 98, "php local file inclusion": 98, "forced browsing": 425,
    "missing required cryptographic step": 325, "type confusion": 843, "weak cryptography for passwords": 261,
    "security through obscurity": 656, "file and directory information exposure": 538,
    "missing authentication for critical function": 306, "buffer underflow": 124,
    "insecure temporary file": 377,
    "failure to sanitize special elements into a different plane (special element injection)": 75,
    "ldap injection": 90, "information exposure through timing discrepancy": 208,
    "leftover debug code (backdoor)": 489, "nosql injection": 943, "encoding error": 172,
    "reversible one-way hash": 328, "loop with unreachable exit condition ('infinite loop')": 835,
    "reusing session ids (aka session replay)": 294, "insecure default initialization of resource": 1188,
    "improper link resolution before file access ('link following')": 59, "unchecked error condition": 391,
}
SEVERITIES = {"none", "low", "medium", "high", "critical"}


def cwe_names():
    names = {}
    for line in (ROOT / "normalized/cwe.jsonl").open():
        c = json.loads(line)
        names[c["name"].lower()] = c["id"]
    return names


def section(text, start, end=None):
    i = text.find(start)
    if i < 0:
        return None
    i += len(start)
    j = text.find(end, i) if end else -1
    return text[i: j if j >= 0 else len(text)].strip()


def parse_aj_md(path):
    """Header table (asset identifier), program summary and write-up from one ajaysenr report file."""
    text = path.read_text(encoding="utf-8")
    table = dict(re.findall(r"^\| \*\*(.+?)\*\* \| (.*) \|$", text, re.M))
    summary = section(text, "\n## Program Summary\n", "\n## Vulnerability Details\n")
    if summary:
        summary = re.sub(r"^> ?", "", summary)
        if summary.startswith("*No official summary"):
            summary = None
    body = section(text, "\n## Vulnerability Details\n")
    if body and body.startswith("*No vulnerability information available.*"):
        body = None
    asset = None
    m = re.match(r"(.+?) \((.+)\)$", table.get("Asset", ""))
    if m and m.group(1) != "\u2014":
        asset = m.group(1)
    return {"asset": asset, "summary": summary or None, "body": body or None}


def h1_summary(j):
    parts = [(s.get("category"), (s.get("content") or "").strip()) for s in j.get("summaries") or []]
    parts = [(c, t) for c, t in parts if t]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0][1]
    return "\n\n".join(f"**{(c or 'summary').capitalize()} summary**\n\n{t}" for c, t in parts)


def num(v):
    try:
        return float(v) if v not in (None, "") else None
    except ValueError:
        return None


def main():
    names = cwe_names()

    def cwe_for(weakness):
        if not weakness:
            return []
        w = weakness.lower()
        cid = names.get(w) or H1_CWE.get(w)
        return [cid] if cid else []

    csv_rows = {}
    with (MIRROR / "data.csv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            csv_rows[int(row["link"].rstrip("/").rsplit("/", 1)[1])] = row
    aj = {x["id"]: x for x in json.load((AJ / "index.json").open())}
    cached = {int(p.stem) for p in (MIRROR / "reports").glob("*.json")}
    ids = sorted(set(csv_rows) | set(aj) | cached)

    pays = {}
    for line in (ROOT / "normalized/arkadiyt_scopes.jsonl").open():
        s = json.loads(line)
        if s["source"] == "hackerone":
            pays[s["url"].rstrip("/").rsplit("/", 1)[1].lower()] = s["pays"]

    out = []
    for rid in ids:
        p = MIRROR / "reports" / f"{rid}.json"
        j = json.loads(p.read_text()) if p.exists() else {}
        a = aj.get(rid) or {}
        md = parse_aj_md(AJ / "reports" / f"{rid}.md") if a else {}
        c = csv_rows.get(rid) or {}
        team = j.get("team") or {}
        sev = j.get("severity") or {}

        h1_body = (j.get("vulnerability_information") or "").strip() or None
        body, body_src = (h1_body, "h1_json") if h1_body else (md.get("body"), "ajaysenr" if md.get("body") else None)
        summary = h1_summary(j) or md.get("summary")
        weakness = (j.get("weakness") or {}).get("name") or a.get("weakness") or c.get("vuln_type") or None
        severity = j.get("severity_rating") or sev.get("rating") or a.get("severity")
        bounty = num(j.get("bounty_amount")) or num(a.get("bounty")) or num(c.get("bounty")) or None
        handle = team.get("handle") or a.get("program_handle")
        program = (team.get("profile") or {}).get("name") or a.get("program") or c.get("program") or None
        asset = (j.get("structured_scope") or {}).get("asset_identifier") or md.get("asset")
        asset_type = (j.get("structured_scope") or {}).get("asset_type") or a.get("asset_type")
        votes = j.get("vote_count")
        if votes is None:
            votes = a.get("votes")
        if votes is None and c.get("upvotes"):
            votes = int(c["upvotes"])
        out.append({
            "source": "hackerone",
            "id": str(rid),
            "url": f"https://hackerone.com/reports/{rid}",
            "title": j.get("title") or a.get("title") or c.get("title"),
            "program": program,
            "kind": None,  # set below, once program-level bounty evidence is known
            "severity": severity if severity in SEVERITIES else None,
            "severity_raw": severity,
            "cvss": num(sev.get("score")) if sev.get("score") is not None else num(a.get("cvss")),
            "weakness": weakness,
            "cwe": cwe_for(weakness),
            "bounty_usd": bounty,
            "reporter": (j.get("reporter") or {}).get("username") or a.get("reporter"),
            "status": j.get("substate") or a.get("substate"),
            "submitted_at": j.get("submitted_at") or a.get("reported_at"),
            "disclosed_at": j.get("disclosed_at") or a.get("disclosed_at"),
            "votes": votes,
            "assets": [asset] if asset else [],
            "cve": j.get("cve_ids") or a.get("cve_ids") or [],
            "body_md": body,
            "summary_md": summary,
            "extra": {k: v for k, v in {
                "program_handle": handle,
                "asset_type": asset_type,
                "body_source": body_src,
                "in_sources": [s for s, ok in (("h1_json", bool(j)), ("ajaysenr", bool(a)), ("reddelexc_csv", bool(c))) if ok],
                "state": j.get("state"),
                "visibility": j.get("visibility") or a.get("visibility"),
                "cvss_metrics": sev.get("metrics") or sev.get("cvss_4_point_0_metrics"),
                "original_report_id": j.get("original_report_id"),
                "has_bounty": j.get("has_bounty?"),
                "offers_bounties": team.get("offers_bounties"),
                "csv_vuln_type": c.get("vuln_type") or None,
                "csv_upvotes": int(c["upvotes"]) if c.get("upvotes") else None,
                "csv_bounty": num(c.get("bounty")),
            }.items() if v not in (None, [], {})},
        })

    paid = {r["extra"].get("program_handle") or r["program"] for r in out
            if r["bounty_usd"] or r["extra"].get("has_bounty") or r["extra"].get("offers_bounties")}
    for r in out:
        handle = r["extra"].get("program_handle")
        key = handle or r["program"]
        no_bounty_program = key not in paid and (
            pays.get((handle or "").lower()) is False
            or "vdp" in (r["program"] or "").lower() or "vdp" in (handle or "").lower())
        r["kind"] = "vdp" if no_bounty_program else "bug_bounty"

    tmp = OUT.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.rename(OUT)
    print(f"wrote {len(out)} rows to {OUT}")


if __name__ == "__main__":
    main()
