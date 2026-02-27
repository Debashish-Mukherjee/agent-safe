from __future__ import annotations

import argparse
import json
import socket
import socketserver
import threading
from datetime import datetime, timezone
from pathlib import Path


def _match_domain(host: str, allow_domains: list[str]) -> bool:
    for allowed in allow_domains:
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class AllowProxyHandler(socketserver.StreamRequestHandler):
    allow_domains: list[str] = []
    allow_ports: list[int] = [443]
    log_file: Path

    def _log(self, entry: dict[str, object]) -> None:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            **entry,
        }
        with self.log_file.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")

    def handle(self) -> None:
        line = self.rfile.readline().decode("utf-8", errors="ignore").strip()
        if not line:
            return

        parts = line.split()
        if len(parts) < 3:
            return

        method, target, _proto = parts[0], parts[1], parts[2]

        # consume headers
        while True:
            hdr = self.rfile.readline()
            if not hdr or hdr in {b"\r\n", b"\n"}:
                break

        if method.upper() != "CONNECT":
            self.wfile.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            self._log({"decision": "BLOCK", "reason": "method_not_allowed", "method": method, "target": target})
            return

        host, sep, port_str = target.partition(":")
        if not sep:
            port_str = "443"
        try:
            port = int(port_str)
        except ValueError:
            self.wfile.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            self._log({"decision": "BLOCK", "reason": "bad_port", "target": target})
            return

        if not _match_domain(host, self.allow_domains):
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            self._log({"decision": "BLOCK", "reason": "domain_not_allowlisted", "host": host, "port": port})
            return

        if port not in self.allow_ports:
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            self._log({"decision": "BLOCK", "reason": "port_not_allowlisted", "host": host, "port": port})
            return

        try:
            upstream = socket.create_connection((host, port), timeout=5)
        except OSError as exc:
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            self._log({"decision": "BLOCK", "reason": f"connect_failed:{exc}", "host": host, "port": port})
            return

        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._log({"decision": "ALLOW", "reason": "connect_allow", "host": host, "port": port})

        def forward(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass

        t1 = threading.Thread(target=forward, args=(self.connection, upstream), daemon=True)
        t2 = threading.Thread(target=forward, args=(upstream, self.connection), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        upstream.close()


def run_proxy(host: str, port: int, allow_domains: list[str], allow_ports: list[int], log_file: Path) -> None:
    AllowProxyHandler.allow_domains = allow_domains
    AllowProxyHandler.allow_ports = allow_ports
    AllowProxyHandler.log_file = log_file

    server = ThreadingTCPServer((host, port), AllowProxyHandler)
    print(f"allow-proxy listening on {host}:{port}")
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentSafe domain allowlist CONNECT proxy")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--allow-domain", action="append", default=[])
    parser.add_argument("--allow-port", action="append", type=int, default=[443])
    parser.add_argument("--log-file", default="/tmp/agentsafe-proxy.log.jsonl")
    args = parser.parse_args()
    run_proxy(
        host=args.host,
        port=args.port,
        allow_domains=args.allow_domain,
        allow_ports=args.allow_port,
        log_file=Path(args.log_file),
    )


if __name__ == "__main__":
    main()
