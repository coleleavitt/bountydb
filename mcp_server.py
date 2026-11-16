#!/usr/bin/env python3
"""MCP server for bountydb - search disclosed bug bounty reports, scopes, and attack patterns."""
import json, sqlite3
from pathlib import Path
from fastmcp import FastMCP

DB = Path(__file__).parent / "bountydb.sqlite"
mcp = FastMCP("bountydb", instructions="Search disclosed bug bounty reports from HackerOne, Bugcrowd, Code4rena, Immunefi, and pentester.land writeups. Also search program scopes and CWE/CAPEC attack patterns.")

def get_db():
    return sqlite3.connect(DB, check_same_thread=False)

@mcp.tool()
def search_reports(query: str, source: str = None, severity: str = None, limit: int = 20) -> str:
    """Full-text search disclosed bug bounty reports by title, body, weakness, or program.
    
    Args:
        query: Search terms (FTS5 syntax: AND is implicit, OR for alternatives, - to exclude)
        source: Filter by source (hackerone, bugcrowd, code4rena, immunefi, pentesterland)
        severity: Filter by severity (critical, high, medium, low, none)
        limit: Max results (default 20, max 100)
    """
    conn = get_db()
    c = conn.cursor()
    limit = min(limit, 100)
    where = []
    args = [query]
    if source: where.append("source = ?"); args.append(source)
    if severity: where.append("severity = ?"); args.append(severity.lower())
    w = " AND ".join(where) if where else "1=1"
    q = f"""SELECT r.id, r.source, r.title, r.program, r.severity, r.bounty_usd, r.weakness, r.url
            FROM reports r JOIN reports_fts ON r.rowid = reports_fts.rowid
            WHERE reports_fts MATCH ? AND {w} ORDER BY rank LIMIT ?"""
    rows = c.execute(q, args + [limit]).fetchall()
    conn.close()
    if not rows: return "No reports found."
    return "\n".join(f"[{r[1]}] {r[0]}: {r[2]} | {r[3]} | {r[4]} | ${r[5] or 0} | {r[6]} | {r[7]}" for r in rows)

@mcp.tool()
def get_report(report_id: str) -> str:
    """Get full details of a report by its ID."""
    conn = get_db()
    c = conn.cursor()
    row = c.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    conn.close()
    if not row: return f"Report {report_id} not found."
    cols = ["id","source","kind","url","title","program","severity","bounty_usd","weakness","cwe_id","reporter","disclosed_at","submitted_at","body_md","extra"]
    d = dict(zip(cols, row))
    body = d.pop("body_md") or "(no body)"
    return f"""# {d['title']}
Source: {d['source']} | Program: {d['program']} | Severity: {d['severity']} | Bounty: ${d['bounty_usd'] or 0}
Weakness: {d['weakness']} | CWE: {d['cwe_id']} | Reporter: {d['reporter']}
Disclosed: {d['disclosed_at']} | URL: {d['url']}

{body[:8000]}{"..." if len(body) > 8000 else ""}"""

@mcp.tool()
def search_scopes(query: str, source: str = None, pays_bounty: bool = None, limit: int = 50) -> str:
    """Search program scopes (targets in scope for bug bounty programs).
    
    Args:
        query: Search by program name or target (domain, URL, app)
        source: Filter by platform (hackerone, bugcrowd, intigriti, yeswehack, immunefi, hackenproof)
        pays_bounty: Filter to only paid programs (True) or VDPs (False)
        limit: Max results (default 50, max 200)
    """
    conn = get_db()
    c = conn.cursor()
    limit = min(limit, 200)
    where = []
    args = [query]
    if source: where.append("source = ?"); args.append(source)
    if pays_bounty is not None: where.append("pays = ?"); args.append(1 if pays_bounty else 0)
    w = " AND ".join(where) if where else "1=1"
    q = f"""SELECT s.source, s.program, s.target, s.type, s.max_bounty_usd, s.scope
            FROM scopes s JOIN scopes_fts ON s.rowid = scopes_fts.rowid
            WHERE scopes_fts MATCH ? AND {w} ORDER BY rank LIMIT ?"""
    rows = c.execute(q, args + [limit]).fetchall()
    conn.close()
    if not rows: return "No scopes found."
    return "\n".join(f"[{r[0]}] {r[1]}: {r[2]} ({r[3]}) max=${r[4] or '?'} {r[5]}" for r in rows)

@mcp.tool()
def search_attack_patterns(query: str, limit: int = 20) -> str:
    """Search CWE weaknesses and CAPEC attack patterns.
    
    Args:
        query: Search terms (name, description, mitigations, examples)
        limit: Max results (default 20)
    """
    conn = get_db()
    c = conn.cursor()
    q = """SELECT a.id, a.source, a.name, a.severity, a.description
           FROM attack_patterns a JOIN attack_patterns_fts ON a.rowid = attack_patterns_fts.rowid
           WHERE attack_patterns_fts MATCH ? ORDER BY rank LIMIT ?"""
    rows = c.execute(q, (query, min(limit, 50))).fetchall()
    conn.close()
    if not rows: return "No attack patterns found."
    return "\n".join(f"[{r[1]}] {r[0]}: {r[2]} ({r[3] or 'N/A'})\n  {(r[4] or '')[:200]}..." for r in rows)

@mcp.tool()
def get_attack_pattern(pattern_id: str) -> str:
    """Get full details of a CWE or CAPEC pattern."""
    conn = get_db()
    c = conn.cursor()
    row = c.execute("SELECT * FROM attack_patterns WHERE id = ?", (pattern_id,)).fetchone()
    conn.close()
    if not row: return f"Pattern {pattern_id} not found."
    cols = ["id","source","name","description","severity","likelihood","related_weaknesses","mitigations","examples","extra"]
    d = dict(zip(cols, row))
    return f"""# {d['id']}: {d['name']}
Source: {d['source']} | Severity: {d['severity']} | Likelihood: {d['likelihood']}

## Description
{d['description'] or 'N/A'}

## Related Weaknesses
{d['related_weaknesses'] or 'N/A'}

## Mitigations
{d['mitigations'] or 'N/A'}

## Examples
{(d['examples'] or 'N/A')[:4000]}"""

@mcp.tool()
def stats() -> str:
    """Get database statistics."""
    conn = get_db()
    c = conn.cursor()
    reports = c.execute("SELECT source, COUNT(*) FROM reports GROUP BY source").fetchall()
    scopes = c.execute("SELECT source, COUNT(*) FROM scopes GROUP BY source").fetchall()
    patterns = c.execute("SELECT source, COUNT(*) FROM attack_patterns GROUP BY source").fetchall()
    conn.close()
    return f"""bountydb statistics:

Reports ({sum(r[1] for r in reports)} total):
{chr(10).join(f"  {r[0]}: {r[1]}" for r in reports)}

Scopes ({sum(s[1] for s in scopes)} total):
{chr(10).join(f"  {s[0]}: {s[1]}" for s in scopes)}

Attack patterns ({sum(p[1] for p in patterns)} total):
{chr(10).join(f"  {p[0]}: {p[1]}" for p in patterns)}"""

if __name__ == "__main__":
    mcp.run()
