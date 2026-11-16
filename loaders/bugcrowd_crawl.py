#!/usr/bin/env python3
"""Bugcrowd public crawler (read-only, unauthenticated GETs, ~1 req/s, resumable).

Raw files go to sources/bugcrowd/:
  crowdstream/page_<n>.json      /crowdstream.json?filter_by=disclosures&page=n
  disclosures/<uuid>.html        /disclosures/<uuid>/<slug>
  listings/<category>_p<n>.json  /engagement_listings.json?category=...
  engagements/<code>.html        /engagements/<code>  (brief page: api endpoints + header props)
  briefs/<code>.json             current published brief version (scope, reward ranges)
  failures.jsonl                 non-200 answers (not retried on resume unless deleted)
"""
import html, json, re, sys, time
from pathlib import Path
import httpx

BASE = "https://bugcrowd.com"
SRC = Path("/home/cole/SiteResearch/bountydb/sources/bugcrowd")
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
client = httpx.Client(base_url=BASE, headers={"User-Agent": UA}, follow_redirects=False, timeout=30)
DELAY = 1.1
_last = 0.0


class Blocked(Exception):
    pass


def log_failure(path, status, note=""):
    with open(SRC / "failures.jsonl", "a") as f:
        f.write(json.dumps({"path": path, "status": status, "note": note, "at": time.time()}) + "\n")


def failed_before(path):
    p = SRC / "failures.jsonl"
    return p.exists() and any(json.loads(l)["path"] == path for l in p.open())


def get(path, json_=True):
    """Return text, or None for a non-200 that is not a block (logged)."""
    global _last, DELAY
    for attempt in range(5):
        time.sleep(max(0, DELAY - (time.time() - _last)))
        _last = time.time()
        r = client.get(path, headers={"Accept": "application/json" if json_ else "text/html"})
        if r.status_code == 429:
            wait = int(r.headers.get("retry-after", "60") or 60)
            DELAY = min(DELAY * 2, 10)
            print(f"429 on {path}; sleeping {wait}s, delay now {DELAY}s", flush=True)
            time.sleep(wait)
            continue
        if r.status_code in (403, 503) or "Just a moment" in r.text[:2000] or "challenges.cloudflare.com/cdn-cgi" in r.text[:5000]:
            raise Blocked(f"{r.status_code} on {path}")
        if r.status_code != 200:
            log_failure(path, r.status_code, r.headers.get("location", ""))
            return None
        return r.text
    raise Blocked(f"repeated 429 on {path}")


def save(p, text):
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".part")
    tmp.write_text(text)
    tmp.rename(p)


def crowdstream():
    d = SRC / "crowdstream"
    p1 = d / "page_1.json"
    if not p1.exists():
        save(p1, get("/crowdstream.json?filter_by=disclosures&page=1"))
    total = json.loads(p1.read_text())["pagination_meta"]["total_pages"]
    for n in range(2, total + 1):
        f = d / f"page_{n}.json"
        if not f.exists():
            save(f, get(f"/crowdstream.json?filter_by=disclosures&page={n}"))
    items = {}
    for f in sorted(d.glob("page_*.json")):
        for it in json.loads(f.read_text())["results"]:
            items[it["disclosure_report_url"]] = it
    print(f"crowdstream: {len(items)} disclosures", flush=True)
    return list(items.values())


def disclosures(items):
    d = SRC / "disclosures"
    done = 0
    for it in items:
        path = it["disclosure_report_url"]
        uuid = path.split("/")[2]
        f = d / f"{uuid}.html"
        if f.exists() or failed_before(path):
            continue
        t = get(path, json_=False)
        if t:
            save(f, t)
        done += 1
        if done % 50 == 0:
            print(f"disclosures: fetched {done} new", flush=True)


def listings():
    rows = []
    for cat in ("bug_bounty", "vdp", "pen_test"):
        n = 1
        while True:
            f = SRC / "listings" / f"{cat}_p{n}.json"
            if not f.exists():
                save(f, get(f"/engagement_listings.json?category={cat}&page={n}&sort_by=promoted&sort_direction=desc"))
            d = json.loads(f.read_text())
            rows += [dict(e, category=cat) for e in d["engagements"]]
            if n * d["paginationMeta"]["limit"] >= d["paginationMeta"]["totalCount"]:
                break
            n += 1
    print(f"listings: {len(rows)}", flush=True)
    return rows


def engagement(code):
    """Brief page + current published brief document for one engagement code."""
    page_f = SRC / "engagements" / f"{code}.html"
    path = f"/engagements/{code}"
    if not page_f.exists():
        if failed_before(path):
            return
        t = get(path, json_=False)
        if not t:
            return
        save(page_f, t)
    brief_f = SRC / "briefs" / f"{code}.json"
    if brief_f.exists():
        return
    m = re.search(r'data-api-endpoints="([^"]*)"', page_f.read_text())
    api = json.loads(html.unescape(m.group(1))) if m else {}
    doc = api.get("engagementBriefApi", {}).get("getBriefVersionDocument")
    if not doc or failed_before(doc + ".json"):
        return
    t = get(doc + ".json")
    if t:
        save(brief_f, t)


def main():
    SRC.mkdir(parents=True, exist_ok=True)
    rows = listings()
    codes = []
    for e in rows:
        if e.get("isExternalListing") or not e["briefUrl"].startswith(BASE + "/engagements/"):
            continue
        codes.append(e["briefUrl"].rsplit("/", 1)[1])
    items = crowdstream()
    # engagements referenced by disclosures but no longer listed (ended programs): fetch their page for kind
    codes += sorted({it["engagement_code"] for it in items if it.get("engagement_code")} - set(codes))
    for i, code in enumerate(dict.fromkeys(codes), 1):
        engagement(code)
        if i % 50 == 0:
            print(f"engagements: {i}/{len(set(codes))}", flush=True)
    disclosures(items)
    print("DONE", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Blocked as e:
        print(f"BLOCKED: {e}", flush=True)
        sys.exit(3)
