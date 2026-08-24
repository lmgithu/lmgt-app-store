#!/usr/bin/env python3
"""Setup UI for the Umbrel Newt connector."""

from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

WWW_DIR = Path(os.environ.get("NEWT_WWW_DIR", "/www"))
CONFIG_DIR = Path(os.environ.get("NEWT_CONFIG_DIR", "/config"))
ENV_PATH = CONFIG_DIR / "newt.env"
SETTINGS_PATH = CONFIG_DIR / "settings.json"
STATUS_PATH = WWW_DIR / "status.json"

ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{8,256}$")


def load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def read_env() -> dict:
    values = {
        "PANGOLIN_ENDPOINT": "https://app.pangolin.net",
        "NEWT_ID": "",
        "NEWT_SECRET": "",
    }
    if not ENV_PATH.exists():
        return values
    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def write_env(endpoint: str, newt_id: str, secret: str) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    body = (
        f"PANGOLIN_ENDPOINT={endpoint}\n"
        f"NEWT_ID={newt_id}\n"
        f"NEWT_SECRET={secret}\n"
    )
    ENV_PATH.write_text(body, encoding="utf-8")
    os.chmod(ENV_PATH, 0o600)
    SETTINGS_PATH.write_text(
        json.dumps(
            {
                "endpoint": endpoint,
                "id": newt_id,
                "configured": True,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def normalize_endpoint(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        return

    def _send_bytes(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, payload: dict) -> None:
        self._send_bytes(code, json.dumps(payload).encode("utf-8"), "application/json")

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path in {"/", "/index.html"}:
            html = (WWW_DIR / "index.html").read_bytes()
            self._send_bytes(200, html, "text/html; charset=utf-8")
            return
        if path == "/logo.png":
            logo = WWW_DIR / "logo.png"
            if logo.exists():
                self._send_bytes(200, logo.read_bytes(), "image/png")
                return
        if path in {"/api/status", "/status.json"}:
            settings = load_json(SETTINGS_PATH)
            status = load_json(STATUS_PATH)
            env = read_env()
            self._send_json(
                200,
                {
                    "status": status.get("status", "waiting"),
                    "message": status.get("message", ""),
                    "endpoint": settings.get("endpoint") or env.get("PANGOLIN_ENDPOINT") or "https://app.pangolin.net",
                    "id": settings.get("id") or env.get("NEWT_ID") or "",
                    "configured": bool(settings.get("configured") or env.get("NEWT_ID")),
                },
            )
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/api/save":
            self._send_json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json(400, {"error": "Invalid JSON"})
            return

        endpoint = normalize_endpoint(str(data.get("endpoint", "")))
        newt_id = str(data.get("id", "")).strip()
        secret = str(data.get("secret", "")).strip()
        if not endpoint:
            self._send_json(400, {"error": "Enter a Pangolin URL, for example https://app.pangolin.net"})
            return
        if not ID_RE.match(newt_id) or not SECRET_RE.match(secret):
            self._send_json(400, {"error": "Enter the Newt ID and secret from your Pangolin site."})
            return
        try:
            write_env(endpoint, newt_id, secret)
        except Exception:
            self._send_json(500, {"error": "Could not save credentials."})
            return
        self._send_json(
            200,
            {
                "ok": True,
                "message": "Saved. Restart Newt from Umbrel so it can connect.",
            },
        )


def main() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
