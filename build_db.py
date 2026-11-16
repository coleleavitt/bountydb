#!/usr/bin/env python3
"""Build bountydb.sqlite from normalized JSONL files with FTS5 indexes."""
import json, sqlite3, sys
from pathlib import Path

BDB = Path(__file__).parent
NORM = BDB / "normalized"
DB = BDB / "bountydb.sqlite"

def load_jsonl(path):
    """Yield valid JSON objects, skip malformed lines."""
    bad = 0
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip(): continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            bad += 1
    if bad: print(f"  Skipped {bad} malformed lines in {path.name}")

def main():
    if DB.exists(): DB.unlink()
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    
    c.execute("""CREATE TABLE reports (
        id TEXT PRIMARY KEY, source TEXT, kind TEXT, url TEXT, title TEXT,
        program TEXT, severity TEXT, bounty_usd REAL, weakness TEXT, cwe_id TEXT,
        reporter TEXT, disclosed_at TEXT, submitted_at TEXT, body_md TEXT, extra JSON)""")
    
    c.execute("""CREATE TABLE scopes (
        id INTEGER PRIMARY KEY, source TEXT, program TEXT, url TEXT, pays INTEGER,
        max_bounty_usd REAL, scope TEXT, type TEXT, target TEXT, bounty_eligible INTEGER, extra JSON)""")
    
    c.execute("""CREATE TABLE attack_patterns (
        id TEXT PRIMARY KEY, source TEXT, name TEXT, description TEXT,
        severity TEXT, likelihood TEXT, related_weaknesses TEXT, mitigations TEXT, examples TEXT, extra JSON)""")
    
    c.execute("""CREATE TABLE writeup_links (
        id INTEGER PRIMARY KEY, source TEXT, title TEXT, url TEXT, programs TEXT,
        authors TEXT, bugs TEXT, bounty TEXT, published TEXT, platform TEXT, severity TEXT, cves TEXT, extra JSON)""")
    
    rcount = 0
    for f in NORM.glob("*.jsonl"):
        if f.name in ("arkadiyt_scopes.jsonl", "writeup_links.jsonl", "cwe.jsonl", "capec.jsonl") or "_scopes" in f.name:
            continue
        for d in load_jsonl(f):
            c.execute("INSERT OR IGNORE INTO reports VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (d.get("id"), d.get("source"), d.get("kind"), d.get("url"), d.get("title"),
                 d.get("program"), d.get("severity"), d.get("bounty_usd"), d.get("weakness"), d.get("cwe_id"),
                 d.get("reporter"), d.get("disclosed_at"), d.get("submitted_at"), d.get("body_md"),
                 json.dumps(d.get("extra")) if d.get("extra") else None))
            rcount += 1
    print(f"Reports: {rcount}")
    
    scount = 0
    for f in list(NORM.glob("*_scopes.jsonl")) + [NORM/"arkadiyt_scopes.jsonl"]:
        if not f.exists(): continue
        for d in load_jsonl(f):
            c.execute("INSERT INTO scopes (source,program,url,pays,max_bounty_usd,scope,type,target,bounty_eligible,extra) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (d.get("source"), d.get("program"), d.get("url"), 1 if d.get("pays") else 0,
                 d.get("max_bounty_usd"), d.get("scope"), d.get("type"), d.get("target"),
                 1 if d.get("bounty_eligible") else 0, json.dumps(d.get("extra")) if d.get("extra") else None))
            scount += 1
    print(f"Scopes: {scount}")
    
    acount = 0
    for f in [NORM/"cwe.jsonl", NORM/"capec.jsonl"]:
        if not f.exists(): continue
        for d in load_jsonl(f):
            c.execute("INSERT OR IGNORE INTO attack_patterns VALUES (?,?,?,?,?,?,?,?,?,?)",
                (d.get("id"), d.get("source"), d.get("name"), d.get("description"),
                 d.get("severity"), d.get("likelihood"), json.dumps(d.get("related_weaknesses")),
                 json.dumps(d.get("mitigations")), json.dumps(d.get("examples")),
                 json.dumps({k:v for k,v in d.items() if k not in ("id","source","name","description","severity","likelihood","related_weaknesses","mitigations","examples")})))
            acount += 1
    print(f"Attack patterns: {acount}")
    
    wcount = 0
    if (NORM/"writeup_links.jsonl").exists():
        for d in load_jsonl(NORM/"writeup_links.jsonl"):
            c.execute("INSERT INTO writeup_links (source,title,url,programs,authors,bugs,bounty,published,platform,severity,cves,extra) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (d.get("source"), d.get("title"), d.get("url"), json.dumps(d.get("programs")),
                 json.dumps(d.get("authors")), json.dumps(d.get("bugs")), d.get("bounty"),
                 d.get("published"), d.get("platform"), d.get("severity"), json.dumps(d.get("cves")),
                 json.dumps({k:v for k,v in d.items() if k not in ("source","title","url","programs","authors","bugs","bounty","published","platform","severity","cves")})))
            wcount += 1
    print(f"Writeup links: {wcount}")
    
    c.execute("CREATE VIRTUAL TABLE reports_fts USING fts5(title, body_md, weakness, program, content=reports, content_rowid=rowid)")
    c.execute("INSERT INTO reports_fts(reports_fts) VALUES('rebuild')")
    c.execute("CREATE VIRTUAL TABLE scopes_fts USING fts5(program, target, type, content=scopes, content_rowid=rowid)")
    c.execute("INSERT INTO scopes_fts(scopes_fts) VALUES('rebuild')")
    c.execute("CREATE VIRTUAL TABLE attack_patterns_fts USING fts5(name, description, mitigations, examples, content=attack_patterns, content_rowid=rowid)")
    c.execute("INSERT INTO attack_patterns_fts(attack_patterns_fts) VALUES('rebuild')")
    print("FTS5 indexes built")
    
    c.execute("CREATE INDEX idx_reports_source ON reports(source)")
    c.execute("CREATE INDEX idx_reports_program ON reports(program)")
    c.execute("CREATE INDEX idx_reports_severity ON reports(severity)")
    c.execute("CREATE INDEX idx_scopes_program ON scopes(program)")
    
    conn.commit(); conn.close()
    print(f"Done: {DB} ({DB.stat().st_size/1024/1024:.1f} MB)")

if __name__ == "__main__": main()
