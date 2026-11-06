#!/usr/bin/env python3
"""Volatile development-only Kratos courier sink; never persists recovery codes.

The SMTP port binds to the Docker host gateway for the disposable Foundation
container; the inspection API is loopback-only, requires a random per-run key
and never logs message bodies/credentials or exports artifacts. No external
SMTP service or account is involved.
"""
from __future__ import annotations

import hmac
import json
import os
from email import policy
from email.parser import BytesParser
import re
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

KEY = os.environ.get("BAOBAB_TEST_MAIL_KEY", "")
if len(KEY) < 32 or not re.fullmatch(r"[0-9a-f]{64}", KEY):
    raise SystemExit("disposable secret must be 32 random bytes in hex")
MAIL = []
LOCK = threading.Lock()
MAX = 128 * 1024


class SMTP(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 baobab-disposable-local ESMTP\r\n")
        recipient = None
        while True:
            line = self.rfile.readline(4097)
            if not line or len(line) > 4096:
                break
            cmd = line.decode("ascii", "replace").strip()
            upper = cmd.upper()
            if upper.startswith("EHLO "):
                self.wfile.write(b"250-local-sink\r\n250 8BITMIME\r\n")
            elif upper.startswith("HELO "):
                self.wfile.write(b"250 local-sink\r\n")
            elif upper.startswith("MAIL FROM:"):
                recipient = None
                self.wfile.write(b"250 accepted\r\n")
            elif upper.startswith("RCPT TO:"):
                value = cmd.split(":", 1)[1].strip().strip("<>").lower()
                recipient = value if 3 <= len(value) <= 320 and "@" in value else None
                self.wfile.write(b"250 accepted\r\n" if recipient else b"550 recipient rejected\r\n")
            elif upper == "DATA":
                if not recipient:
                    self.wfile.write(b"503 missing recipient\r\n")
                    continue
                self.wfile.write(b"354 end with dot\r\n")
                received, size = [], 0
                while True:
                    part = self.rfile.readline(4097)
                    if not part or len(part) > 4096:
                        return
                    if part in (b".\r\n", b".\n"):
                        break
                    if part.startswith(b".."):
                        part = part[1:]
                    size += len(part)
                    if size > MAX:
                        return
                    received.append(part)
                # Select ONLY the authenticated SMTP message's text/plain
                # part, never HTML markup, URLs, subject headers or MIME
                # boundaries. Unstructured HTML attributes may contain
                # unrelated digit sequences mistaken for recovery codes.
                # Reject malformed/missing plaintext instead of guessing.
                try:
                    parsed = BytesParser(policy=policy.default).parsebytes(
                        b"".join(received)
                    )
                    if parsed.defects:
                        raise ValueError("malformed MIME envelope")
                    parts = [
                        part for part in parsed.walk()
                        if part.get_content_type() == "text/plain"
                        and part.get_content_disposition() != "attachment"
                    ]
                    if len(parts) != 1:
                        raise ValueError("ambiguous recovery plaintext")
                    plain = parts[0].get_content()
                    if not isinstance(plain, str) or not (0 < len(plain) <= MAX):
                        raise ValueError("invalid recovery plaintext")
                except (ValueError, TypeError, UnicodeError, LookupError):
                    self.wfile.write(b"554 invalid disposable MIME body\r\n")
                    recipient = None
                    continue
                with LOCK:
                    MAIL.append({"recipient": recipient, "body": plain})
                    del MAIL[:-20]
                self.wfile.write(b"250 stored only in memory\r\n")
                recipient = None
            elif upper == "RSET":
                recipient = None
                self.wfile.write(b"250 reset\r\n")
            elif upper == "NOOP":
                self.wfile.write(b"250 ok\r\n")
            elif upper == "QUIT":
                self.wfile.write(b"221 closing\r\n")
                return
            else:
                self.wfile.write(b"502 unsupported\r\n")


class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class API(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):
        path = urlparse(self.path)
        if path.path == "/health":
            return self.send_json(200, {"ready": True})
        supplied = self.headers.get("X-Baobab-Test-Key", "")
        if not hmac.compare_digest(supplied, KEY) or path.path != "/messages":
            return self.send_json(403, {"error": "forbidden"})
        qs = parse_qs(path.query)
        target = qs.get("recipient", [""])[0].lower()
        if not re.fullmatch(r"[a-z0-9._+@-]{3,320}", target):
            return self.send_json(400, {"error": "invalid_recipient"})
        with LOCK:
            results = [m["body"] for m in MAIL if m["recipient"] == target]
        self.send_json(200, {"messages": results[-4:]})

    def send_json(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    smtp = SMTPServer(("0.0.0.0", 1025), SMTP)
    thread = threading.Thread(target=smtp.serve_forever, daemon=True)
    thread.start()
    try:
        ThreadingHTTPServer(("127.0.0.1", 4457), API).serve_forever()
    finally:
        smtp.shutdown()
        smtp.server_close()


if __name__ == "__main__":
    main()
