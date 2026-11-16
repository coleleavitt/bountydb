#!/usr/bin/env python3
"""Standalone recon tool using bountydb.sqlite directly."""
import json
import re
import sqlite3
import sys
from pathlib import Path

DB = Path(__file__).parent / "bountydb.sqlite"

def recon(target: str) -> str:
    """Gather bug bounty intelligence on a target."""
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    out = [f"# Recon: {target}\n"]
    
    # 1. Scope search
    c.execute("""SELECT source, program, target, type, max_bounty_usd, scope
                 FROM scopes WHERE target LIKE ? OR program LIKE ? LIMIT 15""",
              (f"%{target}%", f"%{target}%"))
    scopes = c.fetchall()
    if scopes:
        out.append(f"## In Scope ({len(scopes)} matches)")
        programs = set()
        for s in scopes:
            out.append(f"- [{s[0]}] {s[1]}: {s[2]} ({s[3]}) max=${s[4] or '?'} {s[5]}")
            programs.add(s[1])
        out.append("")
        
        # 2. Prior reports for these programs
        if programs:
            prog_list = list(programs)[:3]
            placeholders = ",".join("?" * len(prog_list))
            c.execute(f"""SELECT id, source, title, program, severity, bounty_usd, weakness, url
                         FROM reports WHERE program IN ({placeholders})
                         ORDER BY bounty_usd DESC NULLS LAST LIMIT 10""", prog_list)
            reports = c.fetchall()
            if reports:
                out.append(f"## Prior Reports on {', '.join(prog_list)}")
                for r in reports:
                    out.append(f"- [{r[1]}] {r[0]}: {r[2][:60]}... | {r[4]} | ${r[5] or 0} | {r[6]}")
                out.append("")
    else:
        out.append("## Not found in bug bounty scopes\n")
        # Try FTS on reports
        c.execute("""SELECT id, source, title, program, severity, bounty_usd, weakness
                     FROM reports r JOIN reports_fts ON r.rowid = reports_fts.rowid
                     WHERE reports_fts MATCH ? LIMIT 10""", (target,))
        reports = c.fetchall()
        if reports:
            out.append(f"## Reports mentioning '{target}'")
            for r in reports:
                out.append(f"- [{r[1]}] {r[0]}: {r[2][:60]}... | {r[4]} | ${r[5] or 0}")
            out.append("")
    
    # 3. Attack patterns hint
    c.execute("""SELECT id, name FROM attack_patterns
                 WHERE name LIKE '%injection%' OR name LIKE '%traversal%' OR name LIKE '%SSRF%'
                 LIMIT 5""")
    patterns = c.fetchall()
    if patterns:
        out.append("## Common Attack Patterns to Check")
        for p in patterns:
            out.append(f"- {p[0]}: {p[1]}")
    
    conn.close()
    return "\n".join(out)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: recon.py <target>")
        print("Examples: recon.py shopify")
        print("          recon.py '*.uber.com'")
        sys.exit(1)
    print(recon(sys.argv[1]))
