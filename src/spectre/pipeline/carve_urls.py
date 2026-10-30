"""
carve_urls.py — carve URLs from a raw image (memory or disk).

Deterministic strings-style sweep: reads the image in overlapping binary
chunks and regex-extracts http/https URLs, deduplicates, and writes a JSON
list. This is the automatable equivalent of `strings image | grep http`
used in many memory-forensics writeups, surfacing paste/file-share/cloud
breadcrumb links for downstream triage.

Usage: carve_urls.py <image> [max_urls]   # prints a JSON list of URLs to stdout
"""

import json
import re
import sys

_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,256}")
_CHUNK = 8 * 1024 * 1024  # 8 MiB
_OVERLAP = 512            # bytes, so a URL spanning a boundary isn't lost


def carve(image: str, max_urls: int = 5000) -> list[str]:
    seen: dict[str, None] = {}
    prev_tail = b""
    with open(image, "rb") as f:
        while True:
            chunk = f.read(_CHUNK)
            if not chunk:
                break
            buf = prev_tail + chunk
            for m in _URL_RE.findall(buf):
                try:
                    url = m.decode("ascii", "strict").rstrip(".,);'\"")
                except UnicodeDecodeError:
                    continue
                if url not in seen:
                    seen[url] = None
                    if len(seen) >= max_urls:
                        return list(seen.keys())
            prev_tail = chunk[-_OVERLAP:]
    return list(seen.keys())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: carve_urls.py <image> [max_urls]", file=sys.stderr)
        sys.exit(2)
    image = sys.argv[1]
    cap = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
    # Emit a JSON list on stdout; run_tool captures it to the case output.
    sys.stdout.write(json.dumps(carve(image, cap)))
