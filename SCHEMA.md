# bountydb normalized format

Every loader writes one JSON object per line to `normalized/<source>.jsonl` (UTF-8). `build_db.py` loads these into
`bountydb.sqlite`. Raw downloads go under `sources/<source>/` so the loader can be re-run offline.

## reports: normalized/<source>.jsonl
| field | type | notes |
|---|---|---|
| source | str | hackerone, bugcrowd, code4rena, immunefi, hackenproof, ... |
| id | str | unique within source (H1 report id, Bugcrowd uuid, `<contest-slug>/H-01`, HAC-858, ...) |
| url | str | canonical public page |
| title | str | |
| program | str or null | program, company or contest name |
| kind | str | bug_bounty, vdp, audit_contest, bug_fix_review, writeup (a researcher's own blog post) |
| severity | str or null | none, low, medium, high, critical (Bugcrowd P1=critical P2=high P3=medium P4=low P5=none) |
| severity_raw | str or null | the platform's own value |
| cvss | float or null | |
| weakness | str or null | the platform's weakness/category name |
| cwe | list[int] | CWE ids when the platform gives them or the weakness name maps cleanly; else [] |
| bounty_usd | float or null | |
| reporter | str or null | |
| status | str or null | resolved, duplicate, informative, ... as given |
| submitted_at | str or null | ISO 8601 date or datetime |
| disclosed_at | str or null | ISO 8601 date or datetime |
| votes | int or null | |
| assets | list[str] | affected assets, targets, repos or contracts |
| cve | list[str] | |
| body_md | str or null | the full write-up as markdown (convert HTML to markdown) |
| summary_md | str or null | a short summary when the platform has one separate from the body |
| extra | object | anything else worth keeping (raw ids, labels, links) |

## scopes: normalized/<source>_scopes.jsonl (optional)
`{source, program, url, pays: bool, max_bounty_usd, scope: "in"|"out", type, target, bounty_eligible, extra}`
