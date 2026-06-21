"""
OWASP Top 10 Payload Organizer
Reads the unified owasp_top10_payloads.json and splits it into structured
folders: payloads/<category_name>/<injection_point>.json

Each file preserves the exact validated schema with no truncation.
"""

import json
import os
import sys
from collections import defaultdict

INPUT_FILE = "owasp_top10_payloads.json"
OUTPUT_DIR = "payloads"

def sanitize_filename(name):
    """Sanitize a string for use as a filename."""
    # Replace path-unfriendly characters
    result = name.replace("/", "_").replace("\\", "_") \
                 .replace(":", "_").replace("*", "_") \
                 .replace("?", "_").replace("\"", "_") \
                 .replace("<", "_").replace(">", "_") \
                 .replace("|", "_").replace(" ", "_").lower()
    # Collapse multiple underscores
    while "__" in result:
        result = result.replace("__", "_")
    result = result.strip("_")
    return result

def main():
    # Read the input file
    if not os.path.exists(INPUT_FILE):
        print(f"ERROR: {INPUT_FILE} not found in current directory", file=sys.stderr)
        sys.exit(1)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    total_input = len(data)
    print(f"Read {total_input} payloads from {INPUT_FILE}")

    # Group by vulnerability_category -> injection_point
    groups = defaultdict(lambda: defaultdict(list))
    categories_seen = set()

    for entry in data:
        cat = entry["vulnerability_category"]
        sub = entry["injection_point"]
        categories_seen.add(cat)
        groups[cat][sub].append(entry)

    # Sort categories for deterministic output
    sorted_cats = sorted(groups.keys())

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    total_written = 0
    total_files = 0

    for cat in sorted_cats:
        # Sanitize category name for folder
        cat_folder = sanitize_filename(cat)
        cat_path = os.path.join(OUTPUT_DIR, cat_folder)
        os.makedirs(cat_path, exist_ok=True)

        # Sort injection points within category
        sorted_subs = sorted(groups[cat].keys())

        for sub in sorted_subs:
            entries = groups[cat][sub]
            sub_filename = sanitize_filename(sub) + ".json"
            sub_path = os.path.join(cat_path, sub_filename)

            with open(sub_path, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2, ensure_ascii=False)

            total_written += len(entries)
            total_files += 1
            print(f"  wrote {len(entries):>4} payloads -> {cat_folder}/{sub_filename}")

    # Write a manifest/README-like summary
    summary = {
        "total_payloads": total_input,
        "total_categories": len(sorted_cats),
        "total_files": total_files,
        "categories": {}
    }

    for cat in sorted_cats:
        cat_folder = sanitize_filename(cat)
        subs = {}
        for sub in sorted(groups[cat].keys()):
            sub_file = sanitize_filename(sub) + ".json"
            subs[sub] = {
                "file": f"{cat_folder}/{sub_file}",
                "count": len(groups[cat][sub])
            }
        summary["categories"][cat] = {
            "folder": cat_folder,
            "total": sum(len(v) for v in groups[cat].values()),
            "files": subs
        }

    summary_path = os.path.join(OUTPUT_DIR, "_manifest.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"\n  wrote manifest -> payloads/_manifest.json")

    print(f"\n{'='*60}")
    print(f"SUMMARY: {total_written} payloads across {total_files} files in {OUTPUT_DIR}/")
    print(f"{'='*60}")

    # Verification: re-read all files and compare count
    print("\nVerifying integrity...")
    roundtrip_count = 0
    for cat in sorted_cats:
        cat_folder = sanitize_filename(cat)
        for sub in sorted(groups[cat].keys()):
            sub_file = sanitize_filename(sub) + ".json"
            sub_path = os.path.join(OUTPUT_DIR, cat_folder, sub_file)
            with open(sub_path, "r", encoding="utf-8") as f:
                reloaded = json.load(f)
            roundtrip_count += len(reloaded)
            if len(reloaded) != len(groups[cat][sub]):
                print(f"  MISMATCH: {cat}/{sub}: expected {len(groups[cat][sub])}, got {len(reloaded)}")

    if roundtrip_count == total_input:
        print(f"  VERIFIED: All {roundtrip_count} payloads round-tripped correctly.")
    else:
        print(f"  ERROR: Expected {total_input}, verified {roundtrip_count}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
