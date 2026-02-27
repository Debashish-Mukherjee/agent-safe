#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def _safe_name(value: str) -> str:
    clean = re.sub(r"[^a-zA-Z0-9._-]+", "_", value)
    return clean.strip("_") or "unknown"


class CaptureHandler(BaseHTTPRequestHandler):
    out_dir: Path

    def log_message(self, format: str, *args):
        _ = (format, args)

    def _write_json(self, code: int, payload: dict):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            payload = {"_raw": raw.decode("utf-8", errors="replace")}

        now = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        req_id = str(payload.get("request_id") or payload.get("id") or "noid")
        filename = f"{now}_{_safe_name(self.path)}_{_safe_name(req_id)}.json"
        target = self.out_dir / filename
        target.write_text(
            json.dumps(
                {
                    "captured_at": datetime.now(UTC).isoformat(),
                    "route": self.path,
                    "headers": dict(self.headers.items()),
                    "payload": payload,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        self._write_json(200, {"ok": True, "saved": str(target)})


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture OpenClaw-like gateway payloads for fixture generation.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9088)
    parser.add_argument("--out", default="agentsafe/tests/fixtures/openclaw/captured")
    args = parser.parse_args()

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    CaptureHandler.out_dir = out_dir
    server = ThreadingHTTPServer((args.host, args.port), CaptureHandler)
    print(f"capture server listening on {args.host}:{args.port}, out={out_dir}")
    server.serve_forever()


if __name__ == "__main__":
    main()
