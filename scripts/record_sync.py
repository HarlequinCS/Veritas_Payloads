"""Append the latest scrape result to the published sync log.

The site and the API both read this file. A run that adds nothing is still recorded.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "_sync_result.json"
LOG = ROOT / "sync-log.json"
API_LOG = ROOT / "api" / "v1" / "sync-log.json"
MAX_RUNS = 400


def load_result() -> dict:
    if not RESULT.exists():
        return {
            "added": 0,
            "total_after": None,
            "elapsed_seconds": None,
            "sources": [],
        }
    return json.loads(RESULT.read_text(encoding="utf-8"))


def load_log() -> dict:
    if not LOG.exists():
        return {"updated_at": None, "dataset_total": None, "runs": []}
    data = json.loads(LOG.read_text(encoding="utf-8"))
    data.setdefault("runs", [])
    return data


def write_log(log: dict) -> None:
    text = json.dumps(log, indent=2, ensure_ascii=False) + "\n"
    LOG.write_text(text, encoding="utf-8", newline="\n")
    API_LOG.parent.mkdir(parents=True, exist_ok=True)
    API_LOG.write_text(text, encoding="utf-8", newline="\n")


def main() -> None:
    result = load_result()
    log = load_log()
    runs = list(log.get("runs") or [])
    run_id = os.environ.get("GITHUB_RUN_ID") or datetime.now(timezone.utc).strftime("local-%Y%m%d%H%M%S")
    if any(str(item.get("run_id")) == str(run_id) for item in runs):
        print(f"Run {run_id} is already in the sync log.")
        write_log(log)
        return

    ran_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    repo = os.environ.get("GITHUB_REPOSITORY")
    server = (os.environ.get("GITHUB_SERVER_URL") or "https://github.com").rstrip("/")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if repo and os.environ.get("GITHUB_RUN_ID") else None
    added = int(result.get("added") or 0)
    total_after = result.get("total_after")
    entry = {
        "run_id": str(run_id),
        "ran_at": ran_at,
        "trigger": os.environ.get("GITHUB_EVENT_NAME") or "local",
        "added": added,
        "total_after": total_after,
        "elapsed_seconds": result.get("elapsed_seconds"),
        "sources": result.get("sources") or [],
        "run_url": run_url,
    }
    runs.insert(0, entry)
    log = {
        "updated_at": ran_at,
        "dataset_total": total_after if total_after is not None else log.get("dataset_total"),
        "runs": runs[:MAX_RUNS],
    }
    write_log(log)
    print(f"Logged sync: +{added:,} payloads, dataset total {log['dataset_total']}")


if __name__ == "__main__":
    main()
