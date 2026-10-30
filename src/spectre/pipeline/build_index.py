#!/usr/bin/env python3
"""
Phase 1: KB Ingestion — chunk SANS posters into sections and build FTS5 index.

Step 2: Clean + chunk by section (heuristic heading detection for poster text)
Step 3: Build FTS5 index at config.INDEX_DB
"""
import re
import sqlite3

from spectre.config import KNOWLEDGE_DIR, INDEX_DB

REFERENCES = KNOWLEDGE_DIR

# ── helpers ──────────────────────────────────────────────────────────

def clean_text(raw: str) -> str:
    """Normalize whitespace, strip page artifacts, consolidate lines."""
    lines = raw.split("\n")
    cleaned = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if cleaned and cleaned[-1] != "":
                cleaned.append("")
            continue
        # Drop pure noise lines (single chars, page numbers, etc.)
        if re.match(r"^(P|F|L|\d{1,3}|©|$|•)$", stripped):
            continue
        cleaned.append(stripped)
    # Collapse multiple blank lines
    text = "\n".join(cleaned)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def detect_sections(text: str) -> list[tuple[str, str]]:
    """
    Heuristic section detection for poster text.
    Sections are split on:
      - UPPERCASE LINES (tool names / topic headings)
      - Lines ending with colon that look like headings
      - Major conceptual breaks
    Returns list of (section_title, section_text).
    """
    lines = text.split("\n")
    sections = []
    current_title = "Overview"
    current_lines = []

    # Patterns that suggest a heading
    heading_patterns = [
        re.compile(r"^[A-Z][A-Z\s/-]{4,60}$"),          # ALL CAPS heading
        re.compile(r"^[A-Z][a-zA-Z\s/-]{3,40}:$"),       # Title case ending with colon
        re.compile(r"^[A-Z][a-z]+ [A-Z][a-z]+.*:$"),     # Two title-case words ending with colon
    ]

    for line in lines:
        stripped = line.strip()
        if not stripped:
            if current_lines:
                current_lines.append("")
            continue

        is_heading = False
        for pat in heading_patterns:
            if pat.match(stripped) and len(stripped.split()) <= 8:
                # Don't treat as heading if it looks like regular text
                if len(stripped) < 100:  # headings are short
                    is_heading = True
                    break

        if is_heading and len(stripped) > 3:
            # Save current section and start new one
            if current_lines or current_title != "Overview":
                body = "\n".join(current_lines).strip()
                if body:
                    sections.append((current_title, body))
            current_title = stripped.rstrip(":")
            current_lines = []
        else:
            current_lines.append(stripped)

    # Last section
    body = "\n".join(current_lines).strip()
    if body:
        sections.append((current_title, body))

    # If no sections detected, return whole doc as one
    if not sections:
        sections.append(("Full Document", text))

    return sections


def extract_ioc_tags(text: str) -> list[str]:
    """Extract artifact-type tags from section text for the FTS5 index."""
    tags = set()
    text_lower = text.lower()

    tag_map = {
        "evtx": [r"\bevent id \d{3,4}\b", r"\bevtx\b", r"\bsecurity\.evtx\b", r"\b4688\b"],
        "prefetch": [r"\bprefetch\b", r"\.pf\b"],
        "amcache": [r"\bamcache\b", r"\bamcache\.hve\b"],
        "registry": [r"\bregistry\b", r"\bhkey\b", r"\breg\b", r"\brun key\b", r"\brunonce\b"],
        "mft": [r"\bmft\b", r"\bmaster file table\b", r"\$mft\b"],
        "lnk": [r"\blnk\b", r"\.lnk\b", r"\bshortcut\b", r"\bshellbags\b"],
        "srum": [r"\bsrum\b", r"\bsystem resource usage\b"],
        "shimcache": [r"\bshimcache\b", r"\bappcompatcache\b"],
        "network": [r"\bzeek\b", r"\bnetflow\b", r"\bpcap\b", r"\bwireshark\b", r"\bip\b", r"\bdns\b"],
        "memory": [r"\bvolatility\b", r"\bvol \b", r"\bmemory\b", r"\bram\b"],
        "disk": [r"\bsleuthkit\b", r"\bmmls\b", r"\bfls\b", r"\bfsstat\b"],
        "ioc": [r"\bhash\b", r"\bsha\d+\b", r"\bmd5\b", r"\bioc\b", r"\bindicator\b"],
        "timeline": [r"\btimeline\b", r"\bplaso\b", r"\blog2timeline\b"],
    }

    for tag, patterns in tag_map.items():
        for pat in patterns:
            if re.search(pat, text_lower):
                tags.add(tag)
                break

    return sorted(tags)


# ── main ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("Phase 1: Chunking posters + building FTS5 index")
    print("=" * 60)

    # Step 2: Chunk each poster
    posters = sorted(REFERENCES.glob("*.md"))
    if not posters:
        print("ERROR: No .md files found in", REFERENCES)
        return

    all_chunks = []  # (poster_name, section_title, chunk_text, artifact_tags)

    for poster_path in posters:
        poster_name = poster_path.stem  # e.g., "Hunt-Evil"
        raw = poster_path.read_text()
        cleaned = clean_text(raw)
        sections = detect_sections(cleaned)

        print(f"\n  {poster_name}: {len(sections)} sections ({len(cleaned):,} chars cleaned)")

        for idx, (title, body) in enumerate(sections):
            # Skip very small sections (noise)
            if len(body) < 40:
                continue
            tags = extract_ioc_tags(title + " " + body[:500])
            all_chunks.append((poster_name, title, body, ",".join(tags)))
            if idx < 3 or idx == len(sections) - 1:
                tag_str = f"[{','.join(tags)}]" if tags else ""
                print(f"    § {title[:60]:60s} {len(body):6,} chars  {tag_str}")

    print(f"\n  Total chunks: {len(all_chunks)}")

    # Step 3: Build FTS5 index (embedded content — no external table needed)
    INDEX_DB.unlink(missing_ok=True)
    conn = sqlite3.connect(str(INDEX_DB))
    conn.execute("PRAGMA journal_mode=WAL")

    conn.execute("""
        CREATE VIRTUAL TABLE poster_fts USING fts5(
            poster_name,
            section_title,
            chunk_text,
            artifact_tags
        )
    """)

    # Insert directly into FTS5
    cursor = conn.cursor()
    for poster_name, section_title, chunk_text, artifact_tags in all_chunks:
        cursor.execute(
            "INSERT INTO poster_fts (poster_name, section_title, chunk_text, artifact_tags) VALUES (?, ?, ?, ?)",
            (poster_name, section_title, chunk_text, artifact_tags),
        )

    conn.commit()

    # Also create a simple chunks table for LIKE exact-match queries
    conn.execute("""
        CREATE TABLE chunks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poster_name TEXT,
            section_title TEXT,
            chunk_text TEXT,
            artifact_tags TEXT
        )
    """)
    for poster_name, section_title, chunk_text, artifact_tags in all_chunks:
        conn.execute(
            "INSERT INTO chunks (poster_name, section_title, chunk_text, artifact_tags) VALUES (?, ?, ?, ?)",
            (poster_name, section_title, chunk_text, artifact_tags),
        )
    conn.commit()

    # Verify
    fts_count = cursor.execute("SELECT COUNT(*) FROM poster_fts").fetchone()[0]
    chunk_count = cursor.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
    print(f"\n  FTS5 index: {fts_count} rows in poster_fts, {chunk_count} in chunks")

    # Test queries — FTS5 for text search, LIKE for exact-match IOC
    print("\n  FTS5 full-text queries:")
    fts_tests = [
        ("volatility", "volatility"),
        ("rundll32", "rundll32"),
        ("prefetch", "Prefetch"),
        ("MITRE T1218", "T1218"),
    ]
    for label, query in fts_tests:
        results = cursor.execute(
            "SELECT poster_name, section_title FROM poster_fts WHERE poster_fts MATCH ? LIMIT 3",
            (query,),
        ).fetchall()
        print(f"    '{label}' → {len(results)} hits")

    print("\n  Exact-match IOC queries (LIKE on chunk_text):")
    like_tests = [
        ("SHA1 hash", "%SHA1%"),
        ("IP address", "%127.0.0.1%"),
        ("Windows path", "%\\\\Windows\\\\Temp%"),
        ("event ID 4688", "%4688%"),
        ("rundll32.exe", "%rundll32.exe%"),
    ]
    for label, pattern in like_tests:
        results = cursor.execute(
            "SELECT poster_name, section_title FROM chunks WHERE chunk_text LIKE ? LIMIT 3",
            (pattern,),
        ).fetchall()
        print(f"    '{label}' → {len(results)} hits")

    conn.close()
    print("\n✓ Phase 1 steps 2-3 complete")


if __name__ == "__main__":
    main()
