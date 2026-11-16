#!/usr/bin/env python3
"""Normalize raw Bugcrowd downloads (sources/bugcrowd/) into normalized/bugcrowd.jsonl and bugcrowd_scopes.jsonl.
Run: uv run --with beautifulsoup4 --with lxml --with markdownify python loaders/bugcrowd_normalize.py
"""
import html, json, re
from datetime import datetime
from pathlib import Path
from bs4 import BeautifulSoup
from markdownify import markdownify

DB = Path("/home/cole/SiteResearch/bountydb")
SRC = DB / "sources" / "bugcrowd"
BASE = "https://bugcrowd.com"
SEVERITY = {1: "critical", 2: "high", 3: "medium", 4: "low", 5: "none"}


def md(h):
    return markdownify(h, heading_style="ATX").strip() or None if h else None


def money(s):
    m = re.fullmatch(r"\$([\d,]+(?:\.\d+)?)", (s or "").strip())
    return float(m.group(1).replace(",", "")) if m else None


def dmy(s):
    try:
        return datetime.strptime(s, "%d %b %Y").date().isoformat()
    except (TypeError, ValueError):
        return None


def react_props(page, cls):
    m = re.search(r'data-react-class="%s" data-react-props="([^"]*)"' % re.escape(cls), page)
    return json.loads(html.unescape(m.group(1))) if m else None


def engagement_info():
    """code -> {kind, product_label, category, listing} from listings and brief pages."""
    info = {}
    for f in sorted((SRC / "listings").glob("*.json")):
        cat = f.name.rsplit("_p", 1)[0]
        for e in json.loads(f.read_text())["engagements"]:
            code = e["briefUrl"].rstrip("/").rsplit("/", 1)[1]
            info[code] = {"category": cat, "listing": e}
    for f in (SRC / "engagements").glob("*.html"):
        m = re.search(r'data-props="([^"]*)"', f.read_text())
        if not m:
            continue
        props = json.loads(html.unescape(m.group(1)))
        hp = props.get("earlyFetchProps", {}).get("headerProps", {})
        i = info.setdefault(f.stem, {})
        i["product_label"] = (hp.get("engagementTypeDetail") or {}).get("productLabel")
        i["header"] = hp
    for code, i in info.items():
        label = i.get("product_label") or ""
        if "disclosure" in label.lower():
            i["kind"], i["kind_source"] = "vdp", "product_label"
        elif label:
            i["kind"], i["kind_source"] = "bug_bounty", "product_label"
        elif i.get("category") == "vdp":
            i["kind"], i["kind_source"] = "vdp", "listing_category"
        elif i.get("category"):
            i["kind"], i["kind_source"] = "bug_bounty", "listing_category"
    return info


def timeline(acts):
    out = []
    for a in acts or []:
        params = {k: v for k, v in (a.get("params") or {}).items() if v not in (None, [], "", False)}
        out.append({"key": a.get("key"), "verb": a.get("verb"), "actor": (a.get("actor") or {}).get("name"),
                    "by_staff": a.get("created_by_staff"), "by_customer": a.get("created_by_customer"),
                    "created_at": a.get("created_at"), "params": params})
    return out


def parse_page(page):
    s = BeautifulSoup(page, "lxml")
    stats = {}
    for li in s.select("ul.bc-disclosure-stats li.bc-stat"):
        t, v = li.find(class_="bc-stat__title"), li.find(class_="bc-stat__fig")
        if t and v:
            stats[t.get_text(strip=True)] = v
    dt = stats.get("Disclosed date")
    summaries = []
    for h in s.find_all("h5", string=re.compile(r"^\s*Summary by")):
        art = h.find_parent("article")
        body = "".join(str(x) for x in h.find_next_siblings()) if art else ""
        summaries.append({"by": h.get_text(strip=True)[len("Summary by"):].strip(), "html": body})
    return {
        "stats": {k: v.get_text(" ", strip=True) for k, v in stats.items()},
        "disclosed_at": dt.find("time")["datetime"] if dt and dt.find("time") else None,
        "summaries": summaries,
        "activities": (react_props(page, "ActivityFeed") or {}).get("activities"),
    }


def reports(info):
    items = {}
    for f in sorted((SRC / "crowdstream").glob("page_*.json"), key=lambda p: int(p.stem.split("_")[1])):
        for it in json.loads(f.read_text())["results"]:
            items.setdefault(it["disclosure_report_url"], it)
    by_name = {}
    for i in info.values():
        name = (i.get("listing") or {}).get("name") or (i.get("header") or {}).get("name")
        if name:
            by_name[name.strip().lower()] = i
    rows, missing = [], 0
    for path, it in items.items():
        uuid = path.split("/")[2]
        pf = SRC / "disclosures" / f"{uuid}.html"
        page = parse_page(pf.read_text()) if pf.exists() else None
        missing += page is None
        code = it.get("engagement_code")
        program = it.get("engagement_name") or ((page or {}).get("stats") or {}).get("Engagement")
        ei = info.get(code) or by_name.get((program or "").strip().lower(), {})
        kind, kind_source = ei.get("kind"), ei.get("kind_source")
        if not kind:
            vdp_hint = "vdp" in (code or "") or "disclosure" in (program or "").lower()
            kind, kind_source = ("vdp", "name_heuristic") if vdp_hint else ("bug_bounty", "default")
        summ = (page or {}).get("summaries") or []
        researcher = [x for x in summ if x["by"] == it.get("researcher_username")] or summ[:1]
        body = md(researcher[0]["html"]) if researcher else None
        text = " ".join(filter(None, [it.get("title"), body]))
        prio = it.get("priority")
        rows.append({
            "source": "bugcrowd",
            "id": uuid,
            "url": BASE + path,
            "title": it.get("title"),
            "program": program,
            "kind": kind,
            "severity": SEVERITY.get(prio),
            "severity_raw": f"P{prio}" if prio else None,
            "cvss": None,
            "weakness": None,
            "cwe": [],
            "bounty_usd": money(it.get("amount")),
            "reporter": it.get("researcher_username"),
            "status": it.get("substate"),
            "submitted_at": it.get("created_at"),
            "disclosed_at": (page or {}).get("disclosed_at") or dmy(it.get("disclosed_at")),
            "votes": None,
            "assets": [it["target"]] if it.get("target") else [],
            "cve": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text, re.I))),
            "body_md": body,
            "summary_md": None,
            "extra": {
                "crowdstream_id": it.get("id"),
                "engagement_code": code,
                "program_hidden_in_crowdstream": not it.get("engagement_name"),
                "engagement_url": BASE + it["engagement_path"] if it.get("engagement_path") else None,
                "kind_source": kind_source,
                "product_label": ei.get("product_label"),
                "amount_raw": it.get("amount"),
                "points": it.get("points"),
                "accepted_at": dmy(it.get("accepted_at")),
                "closed_at": it.get("closed_at"),
                "researcher_profile": it.get("researcher_profile_path"),
                "page_stats": (page or {}).get("stats"),
                "other_summaries": [{"by": x["by"], "md": md(x["html"])} for x in summ if x not in researcher],
                "timeline": timeline((page or {}).get("activities")),
                "page_fetched": page is not None,
            },
        })
    return rows, missing


def scopes(info):
    rows = []
    for f in sorted((SRC / "briefs").glob("*.json")):
        code = f.stem
        d = json.loads(f.read_text())
        ei = info.get(code, {})
        lst = ei.get("listing") or {}
        rs = lst.get("rewardSummary") or {}
        groups = d["data"].get("scope") or []
        cents = [g["rewardRange"].get(f"p{p}MaxCents") or 0 for g in groups if g.get("rewardRange") for p in range(1, 6)]
        max_usd = money(rs.get("maxReward")) or (max(cents) / 100 if cents and max(cents) else None)
        pays = bool(max_usd) or d.get("rewardAllocation") not in (None, "", "no_rewards") and ei.get("kind") == "bug_bounty"
        program = d["data"]["brief"].get("name") or lst.get("name")
        for g in groups:
            rr = g.get("rewardRange") or {}
            ranges = {f"P{p}": {"min_usd": (rr.get(f"p{p}MinCents") or 0) / 100 if rr.get(f"p{p}MinCents") is not None else None,
                                "max_usd": (rr.get(f"p{p}MaxCents") or 0) / 100 if rr.get(f"p{p}MaxCents") is not None else None}
                      for p in range(1, 6)}
            group_pays = any(v["max_usd"] for v in ranges.values())
            for t in g.get("targets") or []:
                rows.append({
                    "source": "bugcrowd",
                    "program": program,
                    "url": f"{BASE}/engagements/{code}",
                    "pays": pays,
                    "max_bounty_usd": max_usd,
                    "scope": "in" if g.get("inScope") else "out",
                    "type": t.get("category"),
                    "target": t.get("uri") or t.get("name") or t.get("ipAddress"),
                    "bounty_eligible": bool(g.get("inScope") and group_pays),
                    "extra": {
                        "engagement_code": code,
                        "kind": ei.get("kind"),
                        "target_name": t.get("name"),
                        "ip_address": t.get("ipAddress") or None,
                        "target_description": t.get("description"),
                        "tags": [x["name"] for x in t.get("tags") or []],
                        "target_group": g.get("name"),
                        "target_group_description_md": md(g.get("descriptionHtml")),
                        "reward_ranges": ranges,
                        "engagement_max_usd": rr["engagementMaxCents"] / 100 if rr.get("engagementMaxCents") else None,
                        "reward_allocation": d.get("rewardAllocation"),
                        "participation": d.get("participation"),
                        "safe_harbor": (d["data"]["brief"].get("safeHarborStatus") or {}).get("status"),
                        "brief_version_id": d.get("id"),
                        "brief_published_at": d.get("publishedAt"),
                        "industry": d.get("industryName"),
                        "listing_category": ei.get("category"),
                        "access_status": lst.get("accessStatus"),
                    },
                })
    return rows


def write(name, rows):
    p = DB / "normalized" / name
    with p.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"{p}: {len(rows)} rows")


if __name__ == "__main__":
    info = engagement_info()
    rows, missing = reports(info)
    write("bugcrowd.jsonl", rows)
    print(f"disclosure pages missing: {missing}")
    write("bugcrowd_scopes.jsonl", scopes(info))
