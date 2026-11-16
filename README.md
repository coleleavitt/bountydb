# bountydb

Local SQLite database aggregating disclosed bug bounty reports, program scopes, and attack patterns from multiple platforms.

## Data Sources

| Source | Reports | Scopes | Notes |
|--------|---------|--------|-------|
| HackerOne | ~15k | 90k+ | Public disclosed reports |
| Code4rena | 6k+ | - | Audit contest findings |
| Immunefi | 3.9k | 5.6k | Web3 audit reports |
| Bugcrowd | 882 | 9.6k | Public disclosures |
| PortSwigger | 153 | - | Research articles |
| pentester.land | 6.5k | - | Writeup links |
| MITRE | 1k+ | - | CWE + CAPEC patterns |

Plus 113k+ program scopes from arkadiyt/bounty-targets-data.

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
├── normalized/          # JSONL files (not in repo)
├── sources/             # Raw data (not in repo)
└── bountydb.sqlite      # Database (not in repo)
```

## Building Your Own Database

1. Run the loaders to fetch data from each platform
2. Data is saved to `sources/` and normalized to `normalized/*.jsonl`
3. Run `python build_db.py` to create `bountydb.sqlite`

The loaders are resumable and rate-limited (~1 req/s).

## License

MIT
