#!/usr/bin/env python3
"""Normalize raw PortSwigger Research downloads (sources/portswigger/) into normalized/portswigger.jsonl
and sources/portswigger/research_index.json.

The research list comes from the infinite-scroll JSON API used by /research/articles
(bundles/cms/research.js): GET /research/data?previousLastId=<last id of previous page>&lastId=-1&pageSize=40,
saved as raw/research_data_pages.json. Article pages are saved as articles/<slug>.html.
Run: uv run --with beautifulsoup4 --with lxml --with markdownify python loaders/portswigger.py
"""
import json, re
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
from markdownify import markdownify

DB = Path("/home/cole/SiteResearch/bountydb")
SRC = DB / "sources" / "portswigger"
BASE = "https://portswigger.net"


def md(h):
    return markdownify(h, heading_style="ATX").strip() or None


def published(text):
    m = re.search(r"(\d{1,2} \w+ \d{4} at \d{2}:\d{2}) UTC", text or "")
    return datetime.strptime(m.group(1), "%d %B %Y at %H:%M").isoformat() + "Z" if m else None


def parse_article(page):
    s = BeautifulSoup(page, "lxml")
    ld = next(json.loads(x.string) for x in s.find_all("script", type="application/ld+json")
              if x.string and '"Article"' in x.string)
    section = s.select_one("div.wrapper > div.section")
    profiles = section.select(".callout-individual-profile")
    authors = [{"name": p.h3.get_text(strip=True), "profile": BASE + p.h3.a["href"] if p.h3.a else None,
                "twitter": (p.select_one('a[href*="twitter.com"], a[href*="x.com"]') or {}).get("href")}
               for p in profiles]
    pub = {li.strong.get_text(strip=True).rstrip(": "): li.get_text(" ", strip=True)
           for li in section.select(".publication-list li") if li.strong}
    tag_links = section.select("a.label-rounded-outline-white")
    tags = [{"name": a.get_text(strip=True), "url": BASE + a["href"]} for a in tag_links]
    for el in section.select("h1, .share-right, .container-relative-medium-content-width, "
                             ".callout-individual-profile, .publication-list, .container-flex-wrap, "
                             "input, a.chevron-before"):
        el.decompose()
    for el, attr in [(e, a) for a in ("href", "src", "poster") for e in section.find_all(attrs={a: True})]:
        if el[attr].startswith("/"):
            el[attr] = BASE + el[attr]
    links = [a["href"] for a in section.find_all("a", href=True)]
    first_p = next((t for t in (p.get_text(" ", strip=True) for p in section.find_all("p")) if len(t) > 40), None)
    meta = {m.get("property") or m.get("name"): m.get("content") for m in s.find_all("meta") if m.get("content")}
    return {
        "ld": ld, "authors": authors, "tags": tags, "body_md": md(str(section)),
        "published_at": published(pub.get("Published")), "updated_at": published(pub.get("Updated")),
        "description": meta.get("description"), "summary": first_p, "image": meta.get("og:image"),
        "pdf_links": sorted({l for l in links if l.lower().split("?")[0].endswith(".pdf")}),
        "related": [BASE + a["href"] for a in s.select(".widget-tile-container a[href]")],
    }


def main():
    pages = json.loads((SRC / "raw" / "research_data_pages.json").read_text())
    tiles = [t for p in pages for t in p["ResultSet"]["Results"]]
    index, out = [], []
    for t in tiles:
        slug = t["url"].rsplit("/", 1)[1]
        a = parse_article((SRC / "articles" / f"{slug}.html").read_text())
        authors = [x["name"] for x in a["authors"]]
        tags = [x["name"] for x in a["tags"]]
        url = BASE + t["url"]
        date = a["published_at"] or a["ld"].get("datePublished")
        index.append({"id": t["id"], "slug": slug, "url": url, "title": a["ld"]["headline"],
                      "tile_title": t["text1"], "tile_subtitle": t["text2"], "authors": authors,
                      "author_profiles": a["authors"], "date": date, "updated": a["updated_at"],
                      "tags": tags, "summary": a["summary"], "meta_description": a["description"], "image": a["image"],
                      "pdf_links": a["pdf_links"], "related": a["related"]})
        out.append({
            "source": "portswigger", "id": slug, "url": url, "title": a["ld"]["headline"],
            "program": None, "kind": "writeup", "severity": None, "severity_raw": None, "cvss": None,
            "weakness": None, "cwe": [], "bounty_usd": None, "reporter": ", ".join(authors) or None,
            "status": None, "submitted_at": None, "disclosed_at": date, "votes": None, "assets": [],
            "cve": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", a["body_md"] or ""))),
            "body_md": a["body_md"], "summary_md": a["summary"],
            "extra": {"cms_id": t["id"], "authors": a["authors"], "tags": a["tags"], "updated_at": a["updated_at"],
                      "image": a["image"], "pdf_links": a["pdf_links"], "related": a["related"],
                      "tile_subtitle": t["text2"]},
        })
    (SRC / "research_index.json").write_text(json.dumps(index, indent=1, ensure_ascii=False))
    with open(DB / "normalized" / "portswigger.jsonl", "w") as f:
        for r in out:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{len(out)} articles")


if __name__ == "__main__":
    main()
