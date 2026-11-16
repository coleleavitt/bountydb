
"""Normalize HackenProof reports/scopes and YesWeHack scopes into bountydb normalized/*.jsonl (see SCHEMA.md).
Run: uv run --with markdownify python normalize_hp_ywh.py"""
import json, re, pathlib, datetime
from markdownify import markdownify

ROOT = pathlib.Path("/home/cole/SiteResearch/bountydb")
SRC, OUT = ROOT / "sources", ROOT / "normalized"
HTML_RE = re.compile(r"<(p|div|br|ul|ol|li|pre|code|h[1-6]|strong|em|a|table|img)\b", re.I)

def md(text):
    if not text: return None
    text = text.replace("\r\n", "\n").strip()
    return markdownify(text, heading_style="ATX").strip() if HTML_RE.search(text) else text

def iso_date(s):
    if not s: return None
    s = re.sub(r"\s+", " ", s.strip())
    for fmt in ("%b %d %Y", "%d %b %Y", "%B %d, %Y", "%Y-%m-%d"):
        try: return datetime.datetime.strptime(s, fmt).date().isoformat()
        except ValueError: pass
    return s

SEV = {"none": "none", "informational": "none", "info": "none", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

def cwe_ids(*texts):
    return sorted({int(x) for t in texts if t for x in re.findall(r"CWE-(\d+)", str(t))})

def load(p):
    return json.loads(p.read_text())

# ---------- HackenProof reports ----------
BODY_FIELDS = [("vulnerability_details", "Vulnerability details"), ("validation_steps", "Validation steps"),
               ("impact", "Impact"), ("recommended_fix", "Recommended fix"), ("additional_info", "Additional info")]

def hp_reports():
    list_items = {}
    for p in sorted((SRC / "hackenproof/report_lists").glob("*/*.json")):
        kind = p.parent.name
        for it in load(p).get("reports", []):
            list_items[it["second_id"]] = (kind, p.name.rsplit("_p", 1)[0], it)
    rows, missing = [], []
    for rid, (ptype, slug, it) in sorted(list_items.items(), key=lambda x: int(re.sub(r"\D", "", x[0]) or 0)):
        dp = SRC / "hackenproof/reports" / f"{rid}.json"
        if not dp.exists():
            missing.append(rid); continue
        d = load(dp)
        vp = d.get("visibility_params") or it.get("visibility_params") or {}
        parts = []
        for key, label in BODY_FIELDS:
            v = md(d.get(key))
            if v: parts.append(f"## {label}\n\n{v}")
        known = {k for k, _ in BODY_FIELDS}
        for k, v in d.items():  # any other long text field the API adds
            if k not in known and isinstance(v, str) and len(v) > 200:
                parts.append(f"## {k.replace('_', ' ').capitalize()}\n\n{md(v)}")
        comments = load(SRC / "hackenproof/reports" / f"{rid}.comments.json").get("comments") if (SRC / "hackenproof/reports" / f"{rid}.comments.json").exists() else None
        history = load(SRC / "hackenproof/reports" / f"{rid}.history.json").get("history") if (SRC / "hackenproof/reports" / f"{rid}.history.json").exists() else None
        sev_raw = d.get("severity") or it.get("severity")
        bounty = d.get("usd_bounty_amount", it.get("usd_bounty_amount"))
        bp = d.get("bounty_program") or it.get("bounty_program") or {}
        target = d.get("target")
        assets = [target] if isinstance(target, str) and target else ([str(target.get("target") or target)] if target else [])
        weakness = d.get("vulnerability_type") or it.get("vulnerability_type")
        rows.append({
            "source": "hackenproof",
            "id": rid,
            "url": f"https://hackenproof.com/reports/{rid}",
            "title": d.get("title") or it.get("title"),
            "program": bp.get("title") or (d.get("company") or {}).get("company_name"),
            "kind": "audit_contest" if (ptype == "audits" or bp.get("audit_program")) else "bug_bounty",
            "severity": SEV.get(str(sev_raw).strip().lower()) if sev_raw else None,
            "severity_raw": sev_raw,
            "cvss": float(d["cvss_score"]) if d.get("cvss_score") not in (None, "") else None,
            "weakness": weakness,
            "cwe": cwe_ids(weakness),
            "bounty_usd": float(bounty) if bounty is not None and vp.get("rewards") else None,
            "reporter": d.get("author_nickname") or it.get("author_nickname"),
            "status": d.get("state"),
            "submitted_at": iso_date(d.get("created_at") or it.get("created_at")),
            "disclosed_at": None,
            "votes": None,
            "assets": assets,
            "cve": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", "\n".join(parts)))),
            "body_md": "\n\n".join(parts) or None,
            "summary_md": None,
            "extra": {
                "program_slug": slug, "program_type": ptype, "company": d.get("company") or it.get("company"),
                "visibility": d.get("visibility"), "visibility_params": vp,
                "attachments": d.get("attachments") or [], "target_raw": target,
                "comments": comments, "history": history,
            },
        })
    return rows, missing

# ---------- HackenProof scopes ----------
def hp_scopes():
    rows = []
    for p in sorted((SRC / "hackenproof/programs").glob("*/*.json")):
        d, ptype, slug = load(p), p.parent.name, p.stem
        maxb = float(d["max_bounty"]) if d.get("max_bounty") not in (None, "") else None
        pays = bool(maxb and maxb > 0)
        url = f"https://hackenproof.com/{'audit-programs' if ptype == 'audits' else 'programs'}/{slug}"
        for s in d.get("scopes") or []:
            out = bool(s.get("out_of_scope"))
            rows.append({
                "source": "hackenproof", "program": d.get("title") or slug, "url": url, "pays": pays,
                "max_bounty_usd": maxb, "scope": "out" if out else "in", "type": s.get("title"),
                "target": s.get("target"),
                "bounty_eligible": (pays and not out and (s.get("criticality") or "None") != "None"),
                "extra": {"program_slug": slug, "program_type": ptype, "criticality": s.get("criticality"),
                          "target_description": s.get("target_description"), "scope_id": s.get("id"),
                          "company": (d.get("company") or {}).get("slug"), "rewards": d.get("rewards"),
                          "min_bounty": d.get("min_bounty"), "kyc_required": d.get("kyc_required"),
                          "poc_required": d.get("poc_required"), "state": d.get("state"),
                          "labels": d.get("labels")},
            })
    return rows

# ---------- YesWeHack scopes ----------
def ywh_scopes():
    rows = []
    for p in sorted((SRC / "yeswehack/programs").glob("*.json")):
        d = load(p); slug = d["slug"]
        cur = (d.get("business_unit") or {}).get("currency")
        maxb = d.get("bounty_reward_max")
        pays = bool(d.get("bounty")) and bool(maxb)
        base = {"source": "yeswehack", "program": d.get("title"), "url": f"https://yeswehack.com/programs/{slug}",
                "pays": pays, "max_bounty_usd": float(maxb) if maxb is not None and cur == "USD" else None}
        common = {"program_slug": slug, "program_type": d.get("type"), "currency": cur, "max_bounty": maxb,
                  "min_bounty": d.get("bounty_reward_min"), "business_unit": (d.get("business_unit") or {}).get("slug")}
        for s in d.get("scopes") or []:
            rows.append({**base, "scope": "in", "type": s.get("scope_type"), "target": s.get("scope"),
                         "bounty_eligible": pays,
                         "extra": {**common, "scope_type_name": s.get("scope_type_name"), "asset_value": s.get("asset_value"),
                                   "reward_grid": d.get(f"reward_grid_{(s.get('asset_value') or '').lower()}")}})
        for s in d.get("out_of_scope") or []:
            rows.append({**base, "scope": "out", "type": None, "target": s if isinstance(s, str) else json.dumps(s),
                         "bounty_eligible": False, "extra": common})
    return rows

def write(name, rows):
    p = OUT / name
    with p.open("w", encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(name, len(rows))

if __name__ == "__main__":
    reps, missing = hp_reports()
    write("hackenproof.jsonl", reps)
    if missing: print("reports listed but not downloaded:", len(missing), missing[:10])
    write("hackenproof_scopes.jsonl", hp_scopes())
    write("yeswehack_scopes.jsonl", ywh_scopes())
