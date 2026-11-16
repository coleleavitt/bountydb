
"""Resumable public crawler for HackenProof disclosed reports + program scopes and YesWeHack program scopes.
Only unauthenticated GETs, ~1 req/s, honors Retry-After on 429, stops on any block/challenge."""
import json, subprocess, sys, time, pathlib, re

ROOT = pathlib.Path("/home/cole/SiteResearch/bountydb/sources")
CURL = ["/home/cole/.local/bin/curl-impersonate", "--impersonate", "chrome120"]
DELAY = 1.0
last = [0.0]
log = open(ROOT / "crawl.log", "a")

def say(*a):
    msg = time.strftime("%H:%M:%S ") + " ".join(str(x) for x in a)
    print(msg, flush=True); log.write(msg + "\n"); log.flush()

class Blocked(Exception): pass

def get_json(url, dest):
    """GET url, save body to dest (only on 200 JSON). Returns parsed JSON, or None on 404."""
    dest = pathlib.Path(dest)
    if dest.exists() and dest.stat().st_size > 0:
        return json.loads(dest.read_text())
    delay = DELAY
    for attempt in range(6):
        wait = delay - (time.time() - last[0])
        if wait > 0: time.sleep(wait)
        last[0] = time.time()
        r = subprocess.run([*CURL, "-s", "--compressed", "-H", "Accept: application/json", "-D", "-", "-o", "-",
                            "-w", "\n__STATUS__%{http_code}", url], capture_output=True)
        out = r.stdout
        idx = out.rfind(b"\n__STATUS__")
        status = int(out[idx + 11:]) if idx >= 0 else 0
        raw = out[:idx]
        sep = raw.find(b"\r\n\r\n")
        headers, body = raw[:sep].decode("latin-1"), raw[sep + 4:]
        # follow-up header blocks (100-continue etc.)
        while body.startswith(b"HTTP/"):
            sep2 = body.find(b"\r\n\r\n"); headers, body = body[:sep2].decode("latin-1"), body[sep2 + 4:]
        if status == 200 and body[:1] in (b"{", b"["):
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            return json.loads(body)
        if status == 404:
            say("404", url); return None
        if status == 429:
            m = re.search(r"(?im)^retry-after:\s*(\d+)", headers)
            ra = int(m.group(1)) if m else 60
            say("429 Retry-After", ra, url)
            time.sleep(ra); delay = max(delay * 2, 2.0); continue
        if status in (403, 503) or b"Just a moment" in body[:5000] or "cf-mitigated" in headers.lower():
            raise Blocked(f"{status} {url}")
        if status >= 500 or status == 0:
            say("retry", status, url); time.sleep(5 * (attempt + 1)); continue
        say("unexpected", status, url, body[:200]); return None
    raise Blocked(f"gave up after retries {url}")

def hackenproof():
    B = "https://hackenproof.com"
    S = ROOT / "hackenproof"
    programs = []
    for kind, key, extra in [("programs", "programs", "&not_audits=true"), ("audits", "audits", "")]:
        page = 1
        while page:
            d = get_json(f"{B}/programs-api/{kind}?page={page}&per_page=10{extra}", S / "lists" / f"{kind}_p{page:03d}.json")
            if not d: break
            programs += [(kind, p["slug"]) for p in d.get(key, [])]
            page = d.get("next_page")
    say("hackenproof programs:", len(programs))
    report_ids = []
    for n, (kind, slug) in enumerate(programs, 1):
        get_json(f"{B}/programs-api/{kind}/{slug}", S / "programs" / kind / f"{slug}.json")
        page = 1
        while page:
            d = get_json(f"{B}/programs-api/{kind}/{slug}/reports?per_page=10&page={page}",
                         S / "report_lists" / kind / f"{slug}_p{page:03d}.json")
            if not d: break
            report_ids += [(kind, slug, r["second_id"]) for r in d.get("reports", [])]
            page = d.get("next_page")
        if n % 25 == 0: say(f"programs {n}/{len(programs)}, reports so far {len(report_ids)}")
    (S / "report_index.json").write_text(json.dumps(report_ids, indent=0))
    say("hackenproof disclosed reports listed:", len(report_ids))
    for n, (kind, slug, rid) in enumerate(report_ids, 1):
        rep = get_json(f"{B}/reports-api/{rid}", S / "reports" / f"{rid}.json")
        vp = (rep or {}).get("visibility_params") or {}
        if vp.get("comments"):
            get_json(f"{B}/reports-api/{rid}/comments?per_page=10&page=1", S / "reports" / f"{rid}.comments.json")
        if vp.get("timeline"):
            get_json(f"{B}/reports-api/{rid}/history?per_page=10&page=1", S / "reports" / f"{rid}.history.json")
        if n % 25 == 0: say(f"reports {n}/{len(report_ids)}")

def yeswehack():
    A = "https://api.yeswehack.com"
    S = ROOT / "yeswehack"
    slugs, page = [], 1
    while True:
        d = get_json(f"{A}/programs?page={page}", S / "lists" / f"programs_p{page:03d}.json")
        if not d: break
        slugs += [p["slug"] for p in d["items"]]
        if page >= d["pagination"]["nb_pages"]: break
        page += 1
    say("yeswehack programs:", len(slugs))
    for slug in slugs:
        get_json(f"{A}/programs/{slug}", S / "programs" / f"{slug}.json")

if __name__ == "__main__":
    try:
        if "ywh" in sys.argv[1:] or not sys.argv[1:]: yeswehack()
        if "hp" in sys.argv[1:] or not sys.argv[1:]: hackenproof()
        say("CRAWL DONE")
    except Blocked as e:
        say("BLOCKED, stopping:", e); sys.exit(3)
