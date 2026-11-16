# bountydb

Local SQLite database aggregating disclosed bug bounty reports, program scopes, and attack patterns from multiple platforms.

## Data Sources

| Source | Reports | Scopes | Notes |
|--------|---------|--------|-------|
| HackerOne | 15,431 | 90,892 | Public disclosed reports |
| Code4rena | 6,054 | - | Audit contest findings (H/M/QA/Gas) |
| pentester.land | 6,527 | - | Researcher writeup links |
| Immunefi | 3,886 | 5,642 | Web3 audit reports |
| Bugcrowd | 882 | 9,590 | Public disclosures |
| HackenProof | 355 | 2,027 | Bug bounty + audit contests |
| PortSwigger | 153 | - | Research articles |
| Intigriti | - | 4,318 | Scopes only |
| YesWeHack | - | 2,679 | Scopes only |

**Totals: 33,288 reports, 121,030 scopes, 1,599 CWE/CAPEC attack patterns**

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

## Directory Structure

```
bountydb/
├── build_db.py          # Build SQLite from JSONL
├── mcp_server.py        # FastMCP server
├── recon.py             # CLI recon tool
├── SCHEMA.md            # Data schema
├── loaders/             # Platform-specific crawlers
├── normalized/          # JSONL files (gitignored)
├── sources/             # Raw data (gitignored)
└── bountydb.sqlite      # Database (gitignored)
```

## Building Your Own Database

1. Run the loaders to fetch data from each platform
2. Data is saved to `sources/` and normalized to `normalized/*.jsonl`
3. Run `python build_db.py` to create `bountydb.sqlite`

The loaders are resumable and rate-limited (~1 req/s).

## License

MIT
