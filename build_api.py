"""
Build a static HTTP API under api/v1 from payloads/.

GitHub can serve these JSON files (raw or GitHub Pages) but cannot run
server-side queries, so every endpoint is a path other systems GET directly.
"""

from __future__ import annotations

import json
import shutil
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PAYLOADS = ROOT / "payloads"
API = ROOT / "api" / "v1"
PAGE_SIZE = 1000
ID_BUCKET = 100000
RAW_BASE = "https://raw.githubusercontent.com/HarlequinCS/Veritas_Payloads/master/api/v1"
PAGES_BASE = "https://harlequincs.github.io/Veritas_Payloads/api/v1"


def slugify(name: str) -> str:
    result = (
        name.replace("/", "_").replace("\\", "_").replace(":", "_")
        .replace("*", "_").replace("?", "_").replace('"', "_")
        .replace("<", "_").replace(">", "_").replace("|", "_")
        .replace("(", "").replace(")", "").replace(" ", "_").lower()
    )
    while "__" in result:
        result = result.replace("__", "_")
    return result.strip("_")


def dump(path: Path, payload, pretty: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if pretty:
        text = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    path.write_text(text + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    manifest = json.loads((PAYLOADS / "_manifest.json").read_text(encoding="utf-8"))
    if API.exists():
        shutil.rmtree(API)

    categories_out = []
    id_maps: dict[int, dict[str, list]] = defaultdict(dict)
    written_pages = 0
    seen = 0

    for name in sorted(manifest["categories"]):
        info = manifest["categories"][name]
        slug = slugify(name)
        records = []
        points = []
        for point in sorted(info["files"]):
            rel = info["files"][point]["file"]
            chunk = json.loads((PAYLOADS / rel).read_text(encoding="utf-8"))
            records.extend(chunk)
            points.append({"injection_point": point, "count": len(chunk)})
        total = len(records)
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE) if total else 0
        for index in range(pages):
            page_no = index + 1
            start = index * PAGE_SIZE
            batch = records[start:start + PAGE_SIZE]
            page_path = f"categories/{slug}/page/{page_no}.json"
            dump(API / page_path, {
                "category": name,
                "slug": slug,
                "page": page_no,
                "page_size": PAGE_SIZE,
                "total": total,
                "pages": pages,
                "prev": f"categories/{slug}/page/{page_no - 1}.json" if page_no > 1 else None,
                "next": f"categories/{slug}/page/{page_no + 1}.json" if page_no < pages else None,
                "results": batch,
            })
            written_pages += 1
            for entry in batch:
                pid = str(entry["payload_id"])
                number = int(pid.rsplit("-", 1)[-1])
                id_maps[number // ID_BUCKET][pid] = [slug, page_no]
        meta = {
            "category": name,
            "slug": slug,
            "count": total,
            "pages": pages,
            "page_size": PAGE_SIZE,
            "injection_points": points,
            "first_page": f"categories/{slug}/page/1.json" if pages else None,
        }
        dump(API / "categories" / f"{slug}.json", meta, pretty=True)
        categories_out.append(meta)
        seen += total
        del records

    categories_out.sort(key=lambda item: (-item["count"], item["category"]))
    dump(API / "categories.json", {
        "total_categories": len(categories_out),
        "total_payloads": seen,
        "categories": categories_out,
    }, pretty=True)

    for bucket, mapping in id_maps.items():
        dump(API / "id-map" / f"{bucket}.json", mapping)

    dump(API / "index.json", {
        "name": "Veritas Payloads API",
        "version": "1",
        "description": "Static JSON API for the OWASP Top 10 payload dataset. Each path is a file. Fetch it with HTTP GET.",
        "total_payloads": seen,
        "total_categories": len(categories_out),
        "page_size": PAGE_SIZE,
        "id_bucket_size": ID_BUCKET,
        "public_base_urls": {
            "github_raw": RAW_BASE,
            "github_pages": PAGES_BASE,
        },
        "endpoints": {
            "index": "index.json",
            "categories": "categories.json",
            "category": "categories/{slug}.json",
            "page": "categories/{slug}/page/{page}.json",
            "id_map": "id-map/{bucket}.json",
        },
        "id_lookup": "bucket = int(payload_id number) // 100000, then id-map/{bucket}.json maps the id to [slug, page]",
    }, pretty=True)

    print(f"API built: {seen:,} payloads, {len(categories_out)} categories, {written_pages} pages")


if __name__ == "__main__":
    main()
