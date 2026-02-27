#!/usr/bin/env python3
from __future__ import annotations

import json
import shlex
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import requests


def _json(handler: BaseHTTPRequestHandler, status: int, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _validate_execute(payload: dict) -> tuple[bool, str]:
    required = ["request_id", "tool", "args"]
    missing = [field for field in required if field not in payload]
    if missing:
        return False, f"missing required fields: {', '.join(missing)}"
    if not isinstance(payload["request_id"], str) or not payload["request_id"]:
        return False, "request_id must be a non-empty string"
    if not isinstance(payload["tool"], str) or not payload["tool"]:
        return False, "tool must be a non-empty string"
    if not isinstance(payload["args"], dict):
        return False, "args must be an object"
    return True, ""


def _run_shell(command_value) -> dict:
    command = command_value if isinstance(command_value, list) else shlex.split(str(command_value))
    if not command:
        return {"stdout": "", "stderr": "empty command", "exit_code": 1}
    proc = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
    return {"stdout": proc.stdout, "stderr": proc.stderr, "exit_code": proc.returncode}


def _http_fetch(url: str) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return {"status": 0, "body": "unsupported URL scheme"}
    resp = requests.get(url, timeout=15)
    return {"status": resp.status_code, "body": resp.text[:2048]}


class LTGHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args):
        _ = (format, args)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(content_length) if content_length else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except json.JSONDecodeError:
            _json(self, 400, {"error": "invalid_json"})
            return

        if self.path == "/v1/tools/plan":
            request_id = str(payload.get("request_id", "plan"))
            _json(
                self,
                200,
                {
                    "request_id": request_id,
                    "decision": "allow",
                    "result": {"plan": ["stub-plan"]},
                },
            )
            return

        if self.path != "/v1/tools/execute":
            _json(self, 404, {"error": "not_found"})
            return

        ok, error_message = _validate_execute(payload)
        if not ok:
            _json(
                self,
                400,
                {
                    "request_id": payload.get("request_id", ""),
                    "decision": "block",
                    "result": {},
                    "error": error_message,
                },
            )
            return

        request_id = payload["request_id"]
        tool = payload["tool"].lower()
        args = payload["args"]

        if tool in {"shell.run", "run", "command"}:
            result = _run_shell(args.get("command") or args.get("cmd") or [])
            _json(self, 200, {"request_id": request_id, "decision": "allow", "result": result})
            return

        if tool in {"http.fetch", "fetch", "browser.fetch"}:
            url = str(args.get("url", ""))
            result = _http_fetch(url)
            _json(self, 200, {"request_id": request_id, "decision": "allow", "result": result})
            return

        _json(
            self,
            400,
            {
                "request_id": request_id,
                "decision": "block",
                "result": {},
                "error": f"unsupported tool: {payload['tool']}",
            },
        )


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8088), LTGHandler)
    print("light-gateway listening on 0.0.0.0:8088")
    server.serve_forever()


if __name__ == "__main__":
    main()
