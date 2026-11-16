"""Immunefi crawler for bountydb. Public unauthenticated GETs only, ~1 request/second, resumable.

Raw files go to sources/immunefi/. Run: uv run --with httpx python loaders/immunefi_crawl.py
"""
import json, random, re, sys, time
from pathlib import Path
import httpx

SRC = Path("/home/cole/SiteResearch/bountydb/sources/immunefi")
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
GHOST_KEY = "ec0d03d8ad1efcc0aabb2c3e97"
client = httpx.Client(headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}, follow_redirects=True, timeout=60)
delay = 1.0
last = 0.0


class Blocked(Exception):
    pass


def get(url):
    """GET at about 1 request/second. Honors Retry-After on 429; stops on a challenge or 403."""
    global delay, last
    for attempt in range(6):
        wait = delay - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        r = client.get(url)
        last = time.time()
        if r.status_code == 429:
            retry = float(r.headers.get("retry-after") or 30)
            delay = min(delay * 2, 10)
            print(f"429 on {url}: sleeping {retry}s, delay now {delay}s", flush=True)
            time.sleep(retry)
            continue
        if r.status_code == 403 or "Just a moment" in r.text[:3000]:
            raise Blocked(f"{r.status_code} challenge/forbidden on {url}")
        if r.status_code >= 500:
            time.sleep(5 * (attempt + 1))
            continue
        return r
    raise RuntimeError(f"gave up on {url}")


def save(path, url, binary=False):
    """Download url to path unless it already exists. Returns the path, or None on a non-200."""
    path = Path(path)
    if path.exists():
        return path
    r = get(url)
    if r.status_code != 200:
        print(f"{r.status_code} {url}", flush=True)
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".part")
    tmp.write_bytes(r.content)
    tmp.rename(path)
    print(f"saved {path.relative_to(SRC)} ({len(r.content)} B)", flush=True)
    return path


def flight(html):
    return "".join(json.loads('"%s"' % p) for p in re.findall(r'self\.__next_f\.push\(\[1,"(.*?)"\]\)</script>', html, re.S))


def obj_after(text, key):
    i = text.find(f'"{key}":')
    return json.JSONDecoder().raw_decode(text[i + len(key) + 3:])[0]


def crawl_reports():
    rep = SRC / "reports"
    save(rep / "llms.txt", "https://reports.immunefi.com/llms.txt")
    save(rep / "search-index.json", "https://reports.immunefi.com/search-index.json")
    first = save(rep / "llms-full" / "0.md", "https://reports.immunefi.com/llms-full.txt")
    n_parts = int(re.search(r"part 1 of (\d+)", first.read_text()).group(1))
    for n in range(1, n_parts):
        save(rep / "llms-full" / f"{n}.md", f"https://reports.immunefi.com/llms-full.txt/{n}")
    # a fixed random sample of single-page .md files, to check the split of llms-full against
    pages = re.findall(r"^- \[.+?\]\((https://reports\.immunefi\.com/[^)]+\.md)\)", (rep / "llms.txt").read_text(), re.M)
    report_pages = [u for u in pages if re.search(r"/\d+-[^/]*\.md$", u)]
    for u in random.Random(7).sample(report_pages, 25):
        save(rep / "md" / u.split("reports.immunefi.com/", 1)[1], u)
    # pages the normalizer could not cut out of llms-full (written by the normalizer)
    missing = rep / "missing_pages.txt"
    if missing.exists():
        for u in missing.read_text().split():
            save(rep / "md" / u.split("reports.immunefi.com/", 1)[1], u)


def crawl_blog():
    blog = SRC / "blog"
    idx = save(blog / "search-index-posts.json",
               f"https://immunefi.ghost.io/blog/ghost/api/content/search-index/posts/?key={GHOST_KEY}")
    save(blog / "search-index-tags.json",
         f"https://immunefi.ghost.io/blog/ghost/api/content/search-index/tags/?key={GHOST_KEY}")
    posts = json.loads(idx.read_text())["posts"]
    for p in posts:
        if "/bug-fix-reviews/" in p["url"]:
            save(blog / "posts" / f"{p['slug']}.html", p["url"])


def crawl_scopes():
    sc = SRC / "scopes"
    page = save(sc / "bug-bounty.html", "https://immunefi.com/bug-bounty/")
    bounties = obj_after(flight(page.read_text()), "bounties")
    (sc / "bounties.json").write_text(json.dumps(bounties, indent=1))
    for b in bounties:
        save(sc / "assets" / f"{b['slug']}.json", f"https://immunefi.com/api/programs/{b['slug']}/assets/")


if __name__ == "__main__":
    steps = sys.argv[1:] or ["reports", "blog", "scopes"]
    try:
        for s in steps:
            print(f"== {s}", flush=True)
            {"reports": crawl_reports, "blog": crawl_blog, "scopes": crawl_scopes}[s]()
    except Blocked as e:
        print(f"BLOCKED: {e}", flush=True)
        sys.exit(3)
    print("CRAWL DONE", flush=True)
