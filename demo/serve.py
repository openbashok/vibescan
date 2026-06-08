#!/usr/bin/env python3
"""Demo HTTP server for vibescan.

Serves the fake "Acme Habits Tracker" site at demo/site/.

- Aliases dotfile paths that can't be tracked verbatim in git
  (e.g. /.env, /.git/config, /.aider.conf.yml) to non-dotted seeds.
- Sets proper Content-Type for /.well-known/* JSON paths and api-catalog.
- Handles markdown content negotiation on `/`: when Accept: text/markdown
  is sent, serves index.md instead of index.html.
- Adds an RFC 8288 Link response header on the homepage.

Usage:
    sudo python3 demo/serve.py            # port 80
    PORT=8080 python3 demo/serve.py       # port 8080 (no sudo)
"""

from __future__ import annotations

import http.server
import os
import socketserver
import sys
from socketserver import ThreadingMixIn
from urllib.parse import urlparse


class ThreadingHTTPServer(ThreadingMixIn, socketserver.TCPServer):
    """Concurrent request handling so vibescan's ThreadPoolExecutor isn't
    bottlenecked by the demo server itself."""
    daemon_threads = True
    allow_reuse_address = True

PORT = int(os.environ.get("PORT", 80))
HOST = os.environ.get("HOST", "0.0.0.0")
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site")

# /.well-known/* (and similar) → on-disk path relative to ROOT
PATH_ALIASES: dict[str, str] = {
    "/.env":                       "_seeds/env",
    "/.aider.conf.yml":            "_seeds/aider.conf.yml",
    "/.aider.chat.history.md":     "_seeds/aider.history.md",
    "/.git/config":                "_seeds/git/config",
    "/.git/HEAD":                  "_seeds/git/HEAD",
}

# Override content-type for these paths (extensionless or wrong default)
JSON_PATHS = {
    "/.well-known/openid-configuration":            "application/json",
    "/.well-known/oauth-authorization-server":      "application/json",
    "/.well-known/oauth-protected-resource":        "application/json",
    "/.well-known/api-catalog":                     "application/linkset+json",
    "/.well-known/mcp/server-card.json":            "application/json",
    "/.well-known/agent-skills/index.json":         "application/json",
    "/.well-known/http-message-signatures-directory": "application/json",
}

# Per-path explicit MIME for seed-aliased files
SEED_CTYPES = {
    "/.env":                       "text/plain; charset=utf-8",
    "/.aider.conf.yml":            "application/yaml",
    "/.aider.chat.history.md":     "text/markdown; charset=utf-8",
    "/.git/config":                "text/plain; charset=utf-8",
    "/.git/HEAD":                  "text/plain; charset=utf-8",
}


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def log_message(self, fmt, *args):
        # Cleaner log line for the demo
        sys.stderr.write(f"  {self.address_string()}  {fmt % args}\n")

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        accept = self.headers.get("Accept", "")

        # Homepage: markdown negotiation + Link header
        if path in ("/", "/index.html"):
            if "text/markdown" in accept:
                self._serve(os.path.join(ROOT, "index.md"),
                            ctype="text/markdown; charset=utf-8")
            else:
                self._serve(os.path.join(ROOT, "index.html"),
                            ctype="text/html; charset=utf-8",
                            extra={"Link": '</.well-known/api-catalog>; rel="api-catalog", '
                                           '</auth.md>; rel="auth"'})
            return

        # Aliased dotfile paths
        if path in PATH_ALIASES:
            on_disk = os.path.join(ROOT, PATH_ALIASES[path])
            ctype = SEED_CTYPES.get(path)
            self._serve(on_disk, ctype=ctype)
            return

        # Well-known JSON paths
        if path in JSON_PATHS:
            on_disk = os.path.join(ROOT, path.lstrip("/"))
            self._serve(on_disk, ctype=JSON_PATHS[path] + "; charset=utf-8")
            return

        # Default behavior (everything else served from ROOT)
        super().do_GET()

    def _serve(self, file_path: str, ctype: str | None = None,
               extra: dict[str, str] | None = None) -> None:
        if not os.path.isfile(file_path):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"404 - not found\n")
            return
        with open(file_path, "rb") as f:
            body = f.read()
        self.send_response(200)
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    if not os.path.isdir(ROOT):
        sys.stderr.write(f"site directory not found: {ROOT}\n")
        return 1

    try:
        with ThreadingHTTPServer((HOST, PORT), Handler) as httpd:
            print(f"vibescan demo  ·  http://{HOST}:{PORT}  ·  root={ROOT}")
            print(f"Ctrl-C to stop.")
            httpd.serve_forever()
    except PermissionError:
        sys.stderr.write(
            f"\nport {PORT} requires root. Re-run with sudo, "
            f"or use a non-privileged port:\n"
            f"  PORT=8080 python3 {sys.argv[0]}\n"
        )
        return 1
    except KeyboardInterrupt:
        print("\nstopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
