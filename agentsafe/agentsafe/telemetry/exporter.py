from __future__ import annotations

import json
from pathlib import Path

import requests


def export_ledger_to_otel(ledger_path: str | Path, endpoint: str, timeout: int = 5) -> int:
    path = Path(ledger_path)
    if not path.exists():
        return 0

    count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        payload = {"event": json.loads(line)}
        response = requests.post(endpoint, json=payload, timeout=timeout)
        response.raise_for_status()
        count += 1
    return count
