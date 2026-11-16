"""Normalize the Immunefi raw downloads (sources/immunefi/) into normalized/immunefi.jsonl and immunefi_scopes.jsonl.

Offline only. Run: uv run --with beautifulsoup4 --with lxml --with markdownify --with python-dateutil python loaders/immunefi_normalize.py
"""
import html, json, re
from pathlib import Path
from bs4 import BeautifulSoup
from dateutil import parser as dateparser
from markdownify import markdownify

BD = Path("/home/cole/SiteResearch/bountydb")
SRC = BD / "sources/immunefi"
REPORTS = "https://reports.immunefi.com/"
SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "insight": "none"}


def page_list():
    """Every page of reports.immunefi.com as (title, url), in llms.txt order (= llms-full order)."""
    text = (SRC / "reports/llms.txt").read_text()
    return re.findall(r"^- \[(.+?)\]\((https://reports\.immunefi\.com/[^)]+\.md)\)", text, re.M)


def split_part(text, plist):
    """Cut one llms-full part into its pages. A page starts at the next '# ' line that names its report id
    (index pages: the next '# ' line followed by '## Reports by Severity'). Unmatched pages map to None."""
    heads = [m.start() for m in re.finditer(r"(?m)^# ", text)]
    starts, hi = [], 0
    for title, _ in plist:
        rid = re.match(r"(\d+) - ", title)
        found = None
        for j in range(hi, len(heads)):
            line = text[heads[j]:text.find("\n", heads[j])]
            if rid:
                ok = re.search(rf"(?<!\d){rid.group(1)}(?!\d)", line) is not None
            else:
                ok = "## Reports by Severity" in text[heads[j]:heads[j] + 400] or (j == 0 and hi == 0)
            if ok:
                found = j
                break
        starts.append(None if found is None else heads[found])
        if found is not None:
            hi = found + 1
    out = {}
    for i, (_, url) in enumerate(plist):
        if starts[i] is None:
            out[url] = None
            continue
        end = next((s for s in starts[i + 1:] if s is not None), len(text))
        out[url] = text[starts[i]:end].rstrip("\n") + "\n"
    return out


def unescape(s):
    s = re.sub(r"\\([\\`*_{}\[\]()#+\-.!|&])", r"\1", s)
    return html.unescape(s).strip().rstrip("\\").strip()


def parse_date(s):
    s = re.sub(r"\(.*?\)", "", s)
    s = re.sub(r"(\d)(st|nd|rd|th)\b", r"\1", s).replace(" at ", " ")
    try:
        return dateparser.parse(s).isoformat()
    except (ValueError, OverflowError):
        return None


TAG = re.compile(r"^\\?\[?(SC|BC|W ?& ?A|W A|Blockchain_DLT|Blockchain/DLT|Smart Contract|Websites? (?:and|&) App\w*)\s*-?\s*"
                 r"(Critical|High|Medium|Low|Insight)\\?\]?\s*", re.I)


def strip_id_tag(t, rid):
    t = re.sub(rf"^.*?#?{rid}\s*-?\s*", "", unescape(t), count=1)
    t = TAG.sub("", t).strip()
    return re.sub(r"^(?:sc|bc|w a|w&a)\s+(?:critical|high|medium|low|insight)\s+", "", t, flags=re.I)


def clean_title(index_title, heading, body_lines, rid):
    """Title without the id and '[SC - Low]' tag. Prefer the llms.txt link text (properly cased); when it is cut
    off with '...', use a following '## ' line of the page that is not a section name, else the longer of the two."""
    cands = [strip_id_tag(index_title, rid), strip_id_tag(heading[2:], rid)]
    if not cands[0].endswith(("...", "…")):
        return cands[0]
    for line in body_lines[1:6]:
        if line.startswith("## ") and line[3:].strip().lower() not in ("description", "brief/intro", "brief / intro"):
            return unescape(line[3:])
    return max(cands, key=len)


def parse_report(url, index_title, body, ac_name):
    lines = body.split("\n")
    head = re.split(r"(?m)^#{1,3} (?:Description|Brief/Intro)\b", body, maxsplit=1)[0]
    flat = re.sub(r"\*\*", "", head)
    rid_m = re.search(r"Report ID:\s*#?(\d+)", flat) or re.match(r"(\d+) - ", "")
    rid = rid_m.group(1) if rid_m else re.search(r"/(?:[^/]*?)(\d{4,6})-", url).group(1)

    def field(name):
        m = re.search(rf"(?im)^[*\s-]*{name}:\s*(.+)$", flat)
        return unescape(m.group(1)) if m else None

    sub = re.search(r"Submitted on (.+?) by (.+?)\s+for\s+\[(.+?)\]\((.+?)\)", flat)
    reporter = unescape(sub.group(2)).lstrip("@") if sub else None
    if reporter and "redacted" in reporter.lower():
        reporter = None
    sev_raw = field("Report severity") or field("Severity")
    if sev_raw:
        lead = re.match(r"(Critical|High|Medium|Low|Insight)\b", sev_raw, re.I)
        sev_raw = lead.group(1).title() if lead else sev_raw
    if not sev_raw:
        tm = re.search(r"(Critical|High|Medium|Low|Insight)", lines[0], re.I)
        sev_raw = tm.group(1).title() if tm else None
    target = field("Target[^:\n]*")
    target = target.strip("<>").replace("\\", "") if target else None
    impacts = []
    inline = re.search(r"(?im)^[*\s-]*Impacts:[ \t]*(\S.*)$", flat)
    im = re.search(r"(?ims)^[*\s-]*Impacts:\s*$(.*)", flat)
    if inline:
        impacts.append(unescape(inline.group(1)))
    elif im:
        for line in im.group(1).split("\n"):
            m = re.match(r"^\s{0,3}[*-] (.+)", line)
            if m:
                impacts.append(unescape(m.group(1)))
            elif line.strip() and not line.startswith(" "):
                break
    comp = url[len(REPORTS):].split("/")[0]
    return {
        "source": "immunefi",
        "id": f"{comp}/{rid}",
        "url": url[:-3],
        "title": clean_title(index_title, lines[0], lines, rid),
        "program": ac_name,
        "kind": "audit_contest",
        "severity": SEVERITY.get((sev_raw or "").lower()),
        "severity_raw": sev_raw,
        "cvss": None,
        "weakness": None,
        "cwe": [],
        "bounty_usd": None,
        "reporter": reporter,
        "status": None,
        "submitted_at": parse_date(sub.group(1)) if sub else None,
        "disclosed_at": None,
        "votes": None,
        "assets": [target] if target else [],
        "cve": [],
        "body_md": body,
        "summary_md": None,
        "extra": {
            "report_id": rid,
            "competition_slug": comp,
            "competition_link": {"text": unescape(sub.group(3)), "url": sub.group(4)} if sub else None,
            "report_type": field("Report type"),
            "reporter_redacted": bool(sub) and reporter is None,
            "impacts": impacts,
            "heading": lines[0][2:],
            "md_url": url,
        },
    }


def reports():
    plist = page_list()
    bodies = {}
    for n, start in enumerate(range(0, len(plist), 100)):
        bodies.update(split_part((SRC / f"reports/llms-full/{n}.md").read_text(), plist[start:start + 100]))
    ac_name = {REPORTS + it["href"].lstrip("/") + ".md": it["acName"]
               for it in json.loads((SRC / "reports/search-index.json").read_text())}
    singles = SRC / "reports/md"
    rows, missing, mismatch, seen = [], [], [], set()
    for title, url in plist:
        if not re.match(r"\d+ - ", title):
            continue  # competition index pages and the README
        single = singles / url[len(REPORTS):]
        body = bodies.get(url)
        if single.exists():
            if body is not None and body.strip() != single.read_text().strip():
                mismatch.append(url)
            body = single.read_text()
        if body is None:
            missing.append(url)
            continue
        row = parse_report(url, title, body, ac_name.get(url))
        if row["id"] in seen:
            row["id"] += "#2"  # the site publishes a few reports twice under the same id
        seen.add(row["id"])
        rows.append(row)
    (SRC / "reports/missing_pages.txt").write_text("\n".join(missing))
    print(f"reports: {len(rows)} rows, {len(missing)} missing, {len(mismatch)} split/single mismatches {mismatch[:3]}")
    return rows


def blog():
    posts = json.loads((SRC / "blog/search-index-posts.json").read_text())["posts"]
    rows = []
    for p in posts:
        if "/bug-fix-reviews/" not in p["url"]:
            continue
        html = (SRC / "blog/posts" / f"{p['slug']}.html").read_text()
        soup = BeautifulSoup(html, "lxml")
        meta = {(m.get("property") or m.get("name")): m.get("content") for m in soup.find_all("meta")}
        content = soup.select_one("main div.content")
        body = markdownify(str(content), heading_style="ATX", code_language_callback=None).strip() + "\n" if content else None
        if body:
            body = re.sub(r"\n{3,}", "\n\n", body)
        rows.append({
            "source": "immunefi",
            "id": f"blog/{p['slug']}",
            "url": p["url"],
            "title": meta.get("og:title") or p["title"],
            "program": None,
            "kind": "bug_fix_review",
            "severity": None,
            "severity_raw": None,
            "cvss": None,
            "weakness": None,
            "cwe": [],
            "bounty_usd": None,
            "reporter": None,
            "status": None,
            "submitted_at": None,
            "disclosed_at": meta.get("article:published_time"),
            "votes": None,
            "assets": [],
            "cve": re.findall(r"CVE-\d{4}-\d{4,7}", body or ""),
            "body_md": body,
            "summary_md": None,
            "extra": {
                "ghost_id": p["id"],
                "slug": p["slug"],
                "excerpt": p.get("excerpt"),
                "author": meta.get("twitter:data1"),
                "tags": [t.get("content") for t in soup.find_all("meta", property="article:tag")],
                "modified_at": meta.get("article:modified_time"),
            },
        })
    print(f"blog: {len(rows)} rows, {sum(1 for r in rows if r['body_md'])} with body")
    return rows


def scopes():
    bounties = json.loads((SRC / "scopes/bounties.json").read_text())
    rows, missing = [], []
    for b in bounties:
        f = SRC / "scopes/assets" / f"{b['slug']}.json"
        if not f.exists():
            missing.append(b["slug"])
            continue
        for a in json.loads(f.read_text()):
            rows.append({
                "source": "immunefi",
                "program": b["project"],
                "url": f"https://immunefi.com/bug-bounty/{b['slug']}/scope/",
                "pays": bool(b.get("maxBounty")),
                "max_bounty_usd": b.get("maxBounty"),
                "scope": "in",
                "type": a.get("type"),
                "target": a.get("url"),
                "bounty_eligible": True,
                "extra": {
                    "program_slug": b["slug"],
                    "asset_id": a.get("id"),
                    "description": a.get("description"),
                    "added_at": a.get("addedAt"),
                    "revision": a.get("revision"),
                    "is_safe_harbor": a.get("isSafeHarbor"),
                    "is_primacy_of_impact": a.get("isPrimacyOfImpact"),
                    "fund": a.get("fund"),
                    "info": a.get("info"),
                    "program_paused_at": b.get("pausedAt"),
                    "program_tags": b.get("tags"),
                },
            })
    print(f"scopes: {len(rows)} assets from {len(bounties) - len(missing)} programs, missing {missing}")
    return rows


def write(path, rows):
    tmp = path.with_suffix(".jsonl.part")
    with tmp.open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.rename(path)


if __name__ == "__main__":
    out = BD / "normalized"
    write(out / "immunefi.jsonl", reports() + blog())
    write(out / "immunefi_scopes.jsonl", scopes())
