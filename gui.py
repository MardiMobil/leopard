#!/usr/bin/env python3
"""
gui.py - Browser interface for MardiMobil.

Starts a small web server on 127.0.0.1 (never reachable from the network) and
opens it in your browser. Every lookup, score and export goes through
mytool.py, so the CLI and the GUI always give the same results.

Usage:
  mytool --gui                 (or: python gui.py)
  mytool --gui --port 9000 --no-browser

Security:
  * Binds to 127.0.0.1 only, and refuses requests whose Host header isn't
    127.0.0.1/localhost (blocks DNS-rebinding tricks).
  * Each run creates a random token that only the served page knows; every
    API call must send it, so other websites can't drive the tool or change
    your API keys through your browser.
  * API keys are written to the same .env as the CLI and are never sent back
    to the browser, only a masked hint (abcd...wxyz).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import mytool as core

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
MAX_BODY = 5 * 1024 * 1024  # bytes; exports of large bulk runs stay well below this
STATIC = {
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/logo.svg": ("logo.svg", "image/svg+xml"),
    "/rosettes.svg": ("rosettes.svg", "image/svg+xml"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class LocalServer(ThreadingHTTPServer):
    # On Windows SO_REUSEADDR would let us silently share a port that another
    # program already uses; fail instead and pick a free port.
    allow_reuse_address = False
    daemon_threads = True


def source_state(src: core.Source, keys: dict) -> str:
    if not src.key_env:
        return "none"
    if src.id in keys:
        return "ok"
    return "optional" if src.key_optional else "missing"


def make_handler(token: str, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "MardiMobil"
        sys_version = ""

        def log_message(self, fmt, *args):  # keep the terminal quiet
            pass

        # ------------------------------------------------------------ replies
        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            for name, value in (extra or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, obj):
            self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _error(self, status: int, message: str):
            self._json(status, {"error": message})

        # ------------------------------------------------------------- checks
        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in allowed_hosts

        def _token_ok(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Token", ""), token)

        def _read_json(self):
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                raise ValueError("Expected a JSON body.")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if not 0 < length <= MAX_BODY:
                raise ValueError("Request body is empty or too large.")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("Expected a JSON object.")
            return body

        # ------------------------------------------------------------- routes
        def do_GET(self):
            if not self._host_ok():
                return self._error(403, "Forbidden host.")
            path = self.path.split("?", 1)[0]

            if path in ("/", "/index.html"):
                with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as f:
                    html = f.read().replace("{{TOKEN}}", token)
                return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

            if path in STATIC:
                name, ctype = STATIC[path]
                with open(os.path.join(WEB_DIR, name), "rb") as f:
                    return self._send(200, f.read(), ctype)

            if path == "/api/sources":
                if not self._token_ok():
                    return self._error(403, "Invalid token. Reload the page.")
                keys, env_path = core.load_api_keys()
                return self._json(200, {
                    "env_path": env_path or core.SYSTEM_ENV_PATH,
                    "sources": [{
                        "id": s.id,
                        "name": s.name,
                        "kinds": core.describe_kinds(s.kinds),
                        "key_env": s.key_env,
                        "state": source_state(s, keys),
                        "masked": core._mask(keys[s.id]) if s.id in keys else "",
                    } for s in core.SOURCES],
                })

            return self._error(404, "Not found.")

        def do_POST(self):
            if not self._host_ok() or not self._token_ok():
                return self._error(403, "Forbidden. Reload the page.")
            try:
                body = self._read_json()
            except ValueError as e:  # json.JSONDecodeError is a ValueError
                return self._error(400, str(e))
            path = self.path.split("?", 1)[0]

            if path == "/api/lookup":
                return self._lookup(body)
            if path == "/api/keys":
                return self._save_keys(body)
            if path == "/api/export":
                return self._export(body)
            return self._error(404, "Not found.")

        def _lookup(self, body: dict):
            target = str(body.get("target", "")).strip()[:2048]
            ids = body.get("sources")
            if not target:
                return self._error(400, "Enter an IP, domain or hash.")
            if not isinstance(ids, list) or not ids:
                return self._error(400, "Select at least one source.")
            try:
                sources = core.parse_sources(",".join(map(str, ids)))
            except ValueError as e:
                return self._error(400, str(e))
            keys, _ = core.load_api_keys()
            return self._json(200, core.lookup(target, sources, keys))

        def _save_keys(self, body: dict):
            updates = body.get("updates")
            if not isinstance(updates, dict):
                return self._error(400, "Expected {updates: {source_id: key}}.")

            # Validate everything first so a bad entry doesn't leave a half-written file.
            pending = []
            for sid, value in updates.items():
                src = core.SOURCE_BY_ID.get(sid)
                if not src or not src.key_env:
                    return self._error(400, f"Unknown keyed source '{sid}'.")
                value = str(value).replace("﻿", "").strip().strip("'\"")
                if not value:
                    continue
                if any(ch.isspace() for ch in value) or "#" in value:
                    return self._error(400, f"{src.name}: that doesn't look like an API key.")
                pending.append((src, value))

            _, env_path = core.load_api_keys()
            path = env_path or core.SYSTEM_ENV_PATH
            try:
                for src, value in pending:
                    core.set_env_value(path, src.key_env, value)
            except OSError as e:
                return self._error(500, f"Could not write {path}: {e.strerror}")
            return self._json(200, {"saved": [src.id for src, _ in pending], "env_path": path})

        def _export(self, body: dict):
            fmt, reports = body.get("format"), body.get("reports")
            if fmt not in ("csv", "json") or not isinstance(reports, list):
                return self._error(400, "Expected {format: csv|json, reports: [...]}.")
            try:
                text = core.export_text(reports, fmt)
            except (KeyError, TypeError, AttributeError):
                return self._error(400, "Malformed reports.")
            data = text.encode("utf-8-sig" if fmt == "csv" else "utf-8")
            ctype = "text/csv; charset=utf-8" if fmt == "csv" else "application/json; charset=utf-8"
            return self._send(200, data, ctype, {
                "Content-Disposition": f'attachment; filename="mardimobil-report.{fmt}"'})

    return Handler


def serve(port: int = 8765, open_browser: bool = True) -> int:
    core.setup_console(no_color=False)
    try:
        httpd = LocalServer(("127.0.0.1", port), BaseHTTPRequestHandler)
    except OSError:
        print(f"{core.C.YELLOW}[!] Port {port} is busy, using a free one.{core.C.RESET}")
        httpd = LocalServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = httpd.server_address[1]
    httpd.RequestHandlerClass = make_handler(secrets.token_urlsafe(32), port)

    url = f"http://127.0.0.1:{port}/"
    print(f"{core.C.MAGENTA}{core.C.BOLD}MardiMobil GUI{core.C.RESET} running at {core.C.CYAN}{url}{core.C.RESET}")
    print(f"{core.C.DIM}Only this computer can open it. Press Ctrl+C to stop.{core.C.RESET}")
    if open_browser:
        threading.Timer(0.6, webbrowser.open, (url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{core.C.CYAN}GUI stopped.{core.C.RESET}")
    finally:
        httpd.server_close()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mytool --gui", description="MardiMobil browser interface.")
    p.add_argument("--port", type=int, default=8765, help="port to listen on (default: 8765)")
    p.add_argument("--no-browser", action="store_true", help="don't open a browser window")
    args = p.parse_args(argv)
    return serve(args.port, open_browser=not args.no_browser)


if __name__ == "__main__":
    sys.exit(main())
