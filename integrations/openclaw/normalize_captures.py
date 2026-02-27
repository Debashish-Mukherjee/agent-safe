#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def _safe(value: str) -> str:
    return (re.sub(r"[^a-zA-Z0-9._-]+", "_", value).strip("_") or "unknown").lower()


def _extract_payload(path: Path) -> tuple[str, dict]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict) and isinstance(raw.get("payload"), dict):
        route = str(raw.get("route", "unknown"))
        return route, raw["payload"]
    if isinstance(raw, dict):
        return "unknown", raw
    raise ValueError("fixture is not a JSON object")


def normalize_captures(input_dir: Path, output_dir: Path, limit: int) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for src in sorted(input_dir.glob("*.json")):
        if count >= limit:
            break
        try:
            route, payload = _extract_payload(src)
        except (json.JSONDecodeError, ValueError):
            continue

        rid = str(payload.get("request_id") or payload.get("id") or src.stem)
        route_name = _safe(route.replace("/", "_"))
        out_name = f"normalized_{route_name}_{_safe(rid)}.json"
        out_path = output_dir / out_name
        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        count += 1
    return count


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize captured OpenClaw payloads into stable fixture JSON files.")
    parser.add_argument("--in", dest="in_dir", default="agentsafe/tests/fixtures/openclaw/captured")
    parser.add_argument("--out", dest="out_dir", default="agentsafe/tests/fixtures/openclaw")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()

    written = normalize_captures(Path(args.in_dir).resolve(), Path(args.out_dir).resolve(), args.limit)
    print(f"normalized fixtures written: {written}")


if __name__ == "__main__":
    main()
