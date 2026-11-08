"""Print "drift" if api/v1 no longer matches payloads/, else "ok".

The published API is rebuilt from payloads/ by build_api.py. If a rebuild was
ever skipped, the API keeps serving an old snapshot while payloads/ moves on.
This compares the totals and per-category counts so the workflow can repair it.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "payloads" / "_manifest.json"
API_CATEGORIES = ROOT / "api" / "v1" / "categories.json"


def counts_from_manifest() -> dict[str, int]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    out = {}
    for name, info in manifest["categories"].items():
        out[name] = sum(int(f.get("count", 0)) for f in info["files"].values())
    return out


def counts_from_api() -> dict[str, int]:
    data = json.loads(API_CATEGORIES.read_text(encoding="utf-8"))
    return {c["category"]: int(c["count"]) for c in data["categories"]}


def main() -> None:
    try:
        drifted = counts_from_manifest() != counts_from_api()
    except (OSError, KeyError, ValueError, TypeError):
        drifted = True  # missing or unreadable API: rebuild it
    print("drift" if drifted else "ok")


if __name__ == "__main__":
    main()
