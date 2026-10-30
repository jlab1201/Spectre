#!/usr/bin/env python3
"""Extract SANS posters to markdown using pymupdf."""
import fitz

from spectre.config import KNOWLEDGE_DIR

from spectre.config import CACHE_DIR
desktop = CACHE_DIR  # was Desktop, use cache dir instead
output_dir = KNOWLEDGE_DIR
output_dir.mkdir(parents=True, exist_ok=True)

posters = {
    "Hunt-Evil.pdf": "Hunt-Evil.md",
    "Network-Forensics-Poster.pdf": "Network-Forensics-Poster.md",
    "Poster_Threat-Intelligence-Consumption.pdf": "Threat-Intelligence-Consumption.md",
    "Hex-File-Regex-Cheatsheet.pdf": "Hex-File-Regex-Cheatsheet.md",
    "Zimmerman-Tools-Poster.pdf": "Zimmerman-Tools-Poster.md",
    "Windows-to-Unix-Cheatsheet.pdf": "Windows-to-Unix-Cheatsheet.md",
    "Windows-Forensics-Poster.pdf": "Windows-Forensics-Poster.md",
    "SIFT-Cheatsheet.pdf": "SIFT-Cheatsheet.md",
}

results = []
for pdf_name, md_name in posters.items():
    pdf_path = desktop / pdf_name
    if not pdf_path.exists():
        results.append(f"SKIP: {pdf_name} — not on Desktop")
        continue
    try:
        doc = fitz.open(str(pdf_path))
        full_text = []
        for page_num in range(len(doc)):
            page = doc[page_num]
            text = page.get_text("text")
            if text.strip():
                full_text.append(text.strip())
        doc.close()

        output_path = output_dir / md_name
        raw_text = "\n\n".join(full_text)
        output_path.write_text(raw_text)
        chars = len(raw_text)
        results.append(f"OK  {pdf_name} → {md_name}  ({len(full_text)} pages, {chars:,} chars)")
    except Exception as e:
        results.append(f"FAIL {pdf_name} — {e}")

print("\n".join(results))
