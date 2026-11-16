# bountydb

Local SQLite database aggregating disclosed bug bounty reports, program scopes, and attack patterns from multiple platforms.

## Data Sources

| Source | Reports | Scopes | Body Coverage |
|--------|---------|--------|---------------|
| HackerOne | 15,431 | 90,892 | 65% |
| pentester.land | 6,527 | - | 77% |
| Code4rena | 6,054 | - | 100% |
| Immunefi | 3,886 | 5,642 | 100% |
| Bugcrowd | 882 | 9,590 | 99% |
| HackenProof | 355 | 2,027 | 86% |
| PortSwigger | 153 | - | 100% |
| Intigriti | - | 4,318 | - |
| YesWeHack | - | 2,679 | - |

**Totals: 33,288 reports (25,767 with body_md), 121,030 scopes, 1,599 CWE/CAPEC attack patterns**

## Quick Start

```bash
# Build the database (requires normalized/*.jsonl files)
python build_db.py

# Quick recon on a target
python recon.py shopify

# Start MCP server
uv run --with fastmcp python mcp_server.py
```

## MCP Tools

Register with Claude Code:
```bash
claude mcp add bountydb -- uv run --with fastmcp python /path/to/mcp_server.py
```

Available tools:
- `search_reports(query, source?, severity?, limit?)` - FTS search reports
- `get_report(report_id)` - Full report details  
- `search_scopes(query, source?, pays_bounty?, limit?)` - Find in-scope targets
- `search_attack_patterns(query, limit?)` - CWE/CAPEC lookup
- `get_attack_pattern(pattern_id)` - Full pattern details
- `stats()` - Database statistics

## Schema

See [SCHEMA.md](SCHEMA.md) for the normalized data format.

## Loaders

Each platform has a crawler and normalizer in `loaders/`:
- `hackerone.py` - Merges data.csv + ajaysenr archive + live API
- `bugcrowd_crawl.py` / `bugcrowd_normalize.py`
- `immunefi_crawl.py` / `immunefi_normalize.py`  
- `crawl_hp_ywh.py` / `normalize_hp_ywh.py` (HackenProof + YesWeHack)
- `crawl_pentesterland.py` / `pentesterland_normalize.py`
- `portswigger.py`

All loaders are resumable and rate-limited (~1 req/s).

## License

MIT
