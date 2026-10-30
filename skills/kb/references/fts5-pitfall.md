# FTS5 External Content Pitfall

## Problem

With an external-content FTS5 table (`content='chunks'`), MATCH returns 0 hits
after plain INSERTs into the content table, while LIKE on `chunks` works.

## Root cause

SQLite does not create sync triggers for external-content FTS5 tables. The
index is only populated if you write the triggers yourself or run
`INSERT INTO poster_fts(poster_fts) VALUES('rebuild')`. Plain inserts into the
content table leave the FTS index empty, so `sqlite_master` shows 0 triggers
and MATCH is silent.

## Failed approach (do NOT use)

```python
# Create content table
conn.execute("CREATE TABLE chunks (...)")

# Create FTS5 with external content
conn.execute("""
    CREATE VIRTUAL TABLE poster_fts USING fts5(
        poster_name, section_title, chunk_text, artifact_tags,
        content='chunks', content_rowid='rowid'
    )
""")

# Insert into content table — triggers should populate FTS5 index
# BUT the triggers were never created → FTS5 is empty
conn.execute("INSERT INTO chunks (...) VALUES (...)")
# FTS5 MATCH returns 0 hits!
```

## Working approach (embedded FTS5 + separate chunks table)

```python
# 1. Create FTS5 with EMBEDDED content (no content= option)
conn.execute("""
    CREATE VIRTUAL TABLE poster_fts USING fts5(
        poster_name, section_title, chunk_text, artifact_tags
    )
""")

# 2. Insert directly into FTS5
conn.execute("INSERT INTO poster_fts (...) VALUES (...)")

# 3. ALSO create a plain chunks table for LIKE exact-match queries
conn.execute("CREATE TABLE chunks (poster_name, section_title, chunk_text, artifact_tags)")
conn.execute("INSERT INTO chunks (...) VALUES (...)")

# Both tables work now:
# - poster_fts MATCH 'prefetch' → 3 hits ✓
# - chunks WHERE chunk_text LIKE '%SHA1%' → 3 hits ✓
```

## Debugging steps (use when FTS5 is silent)

1. Check if the FTS5 table has rows:
   `SELECT COUNT(*) FROM poster_fts`

2. Check if triggers were created (external content approach):
   `SELECT name FROM sqlite_master WHERE type='trigger'`
   If 0 triggers → external content sync is broken.

3. Test direct FTS5 with a known word:
   ```python
   conn.execute("CREATE VIRTUAL TABLE test_fts USING fts5(content TEXT)")
   conn.execute("INSERT INTO test_fts VALUES ('volatility is a forensics tool')")
   conn.execute("SELECT * FROM test_fts WHERE test_fts MATCH 'volatility'").fetchall()
   ```
   If this returns results, FTS5 itself works — the issue is content sync.

4. Check if the term actually appears in the data:
   `SELECT COUNT(*) FROM chunks WHERE chunk_text LIKE '%volatility%'`
   If 0 → the term isn't in the extracted text (poster layout issue, not FTS5 bug).

## Environment notes

- SQLite version: system default on Ubuntu 24.04
- Default unicode61 tokenizer is case-insensitive for ASCII letters
- FTS5 does NOT handle punctuation-heavy tokens (IPs, paths, hashes) well —
  use LIKE on the chunks table for those
