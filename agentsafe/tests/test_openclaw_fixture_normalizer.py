import json
import subprocess
import sys
from pathlib import Path


def test_normalize_captures_emits_payload_only_fixture(tmp_path: Path):
    in_dir = tmp_path / "captured"
    out_dir = tmp_path / "fixtures"
    in_dir.mkdir(parents=True, exist_ok=True)

    captured = {
        "captured_at": "2026-02-27T10:10:10Z",
        "route": "/v2/tools/execute",
        "headers": {"content-type": "application/json"},
        "payload": {
            "request_id": "demo-123",
            "tool": "shell.run",
            "args": {"command": "ls"},
        },
    }
    (in_dir / "capture.json").write_text(json.dumps(captured), encoding="utf-8")

    script = Path(__file__).resolve().parents[2] / "integrations" / "openclaw" / "normalize_captures.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--in", str(in_dir), "--out", str(out_dir), "--limit", "5"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "normalized fixtures written: 1" in proc.stdout
    files = list(out_dir.glob("normalized_*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["request_id"] == "demo-123"
    assert payload["args"]["command"] == "ls"
