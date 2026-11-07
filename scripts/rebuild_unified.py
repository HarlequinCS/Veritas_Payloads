"""Rewrite owasp_top10_payloads.json from payloads/ in compact form.

GitHub rejects a file at 100 MB. If the compact file would cross that line,
the previous unified file is left in place and the API files stay current.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAYLOADS = ROOT / "payloads"
TARGET = ROOT / "owasp_top10_payloads.json"
LIMIT = 99_000_000


def main() -> None:
    items = []
    for path in sorted(PAYLOADS.rglob("*.json")):
        if path.name == "_manifest.json":
            continue
        items.extend(json.loads(path.read_text(encoding="utf-8")))
    items.sort(key=lambda entry: int(str(entry["payload_id"]).rsplit("-", 1)[-1]))
    text = json.dumps(items, ensure_ascii=False, separators=(",", ":")) + "\n"
    size = len(text.encode("utf-8"))
    print(f"unified payloads: {len(items):,}  compact bytes: {size:,}")
    if size >= LIMIT:
        print("Unified file would exceed GitHub's file limit. Keeping the previous file.")
        return
    TARGET.write_text(text, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()
