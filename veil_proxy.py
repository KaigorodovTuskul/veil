#!/usr/bin/env python3
"""Loopback-only, fail-closed privacy proxy for text-based LLM agents."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import ipaddress
import os
import re
import secrets
import socket
import sys
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from anonymize import CONFIG_DIR, find_candidates, load_rules, load_user_keywords
from veil_protocol import MaskingSession, PolicyError, REQUEST_FIELDS, SSEProcessor, json_bytes, json_loads, mask_request, restore_response

MAX_BODY = 8 * 1024 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
MAX_EVENT = 1024 * 1024
CHATGPT_UPSTREAM = "https://chatgpt.com/backend-api/codex"


class ReasoningCache:
    """Remember account-bound hashes of opaque reasoning received from masked requests."""

    def __init__(self):
        self.entries: OrderedDict[bytes, float] = OrderedDict()
        self.lock = threading.Lock()

    def check(self, account: str, content: str, remember: bool = False) -> bool:
        digest = hashlib.sha256((account + "\0" + content).encode()).digest()
        with self.lock:
            now = time.monotonic()
            while self.entries and (len(self.entries) > 1024 or next(iter(self.entries.values())) < now - 1800):
                self.entries.popitem(last=False)
            if remember or digest in self.entries:
                self.entries[digest] = now
                self.entries.move_to_end(digest)
                while len(self.entries) > 1024:
                    self.entries.popitem(last=False)
                return True
        return False

    def observe(self, account: str, value: object) -> None:
        if not isinstance(value, dict):
            return
        kind = value.get("type")
        if kind in {"response.output_item.added", "response.output_item.done"}:
            items = [value.get("item")]
        elif kind in {None, "response.created", "response.in_progress", "response.completed"}:
            response = value.get("response", value)
            items = response.get("output", []) if isinstance(response, dict) else []
        else:
            return
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and item.get("type") == "reasoning" and isinstance(item.get("encrypted_content"), str):
                    self.check(account, item["encrypted_content"], remember=True)


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], upstream: str, api_key: str, token: str, rules: list[dict], keywords: dict, timeout: float = 120, *, codex_chatgpt: bool = False):
        url = urlsplit(upstream)
        if not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError("Upstream must be an HTTPS base URL without credentials, query or fragment")
        if url.scheme != "https" and not (url.scheme == "http" and _loopback(url.hostname)):
            raise ValueError("Upstream requires HTTPS; HTTP is allowed only for a loopback test server")
        if codex_chatgpt and not (upstream.rstrip("/") == CHATGPT_UPSTREAM or url.scheme == "http" and _loopback(url.hostname)):
            raise ValueError("ChatGPT session credentials may reach only the fixed ChatGPT Codex service or a loopback mock")
        if not _loopback(address[0]):
            raise ValueError("Veil binds only to a loopback address")
        if not token or (not codex_chatgpt and not api_key) or any(char in api_key + token for char in "\r\n"):
            raise ValueError("Non-empty upstream and local credentials are required")
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        self.upstream = url
        self.api_key = api_key
        self.token = token
        self.rules = rules
        self.keywords = keywords
        self.timeout = timeout
        self.codex_chatgpt = codex_chatgpt
        self.reasoning = ReasoningCache()
        self.slots = threading.BoundedSemaphore(16)
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(address, ProxyHandler)

    def process_request(self, request: socket.socket, client_address: tuple) -> None:
        if not self.slots.acquire(blocking=False):
            request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request: socket.socket, client_address: tuple) -> None:
        # The default traceback can include exception messages containing payload data.
        print("Veil: request failed; no request data logged", file=sys.stderr)

    def connect(self, path: str) -> tuple[http.client.HTTPConnection, str]:
        connection_type = http.client.HTTPSConnection if self.upstream.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(self.upstream.hostname, self.upstream.port, timeout=self.timeout)
        base = self.upstream.path.rstrip("/")
        if base.endswith("/v1") or self.codex_chatgpt:
            path = path.removeprefix("/v1")
        return connection, base + path


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Veil"
    sys_version = ""
    server: ProxyServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(30)
        self.sent_headers = False

    def log_message(self, format: str, *args: object) -> None:
        pass

    def send_error(self, code: int, message: str | None = None, explain: str | None = None) -> None:
        self.reply(code, {"error": {"type": "veil_http_error", "message": "Unsupported or malformed HTTP request"}})

    def reply(self, status: int, payload: object) -> None:
        body = json_bytes(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.sent_headers = True
        self.close_connection = True
        self.wfile.write(body)

    def authorize(self) -> bool:
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1 or self.headers.get("Origin"):
            self.reply(403, {"error": {"message": "Browser-origin requests are blocked"}})
            return False
        host = urlsplit("http://" + hosts[0]).hostname
        if not host or not _loopback(host):
            self.reply(403, {"error": {"message": "Loopback Host header required"}})
            return False
        authorization = self.headers.get_all("Authorization", [])
        api_keys = self.headers.get_all("x-api-key", [])
        if self.server.codex_chatgpt:
            local_tokens = self.headers.get_all("X-Veil-Token", [])
            if len(local_tokens) != 1 or not hmac.compare_digest(local_tokens[0].encode(), self.server.token.encode()):
                self.reply(403, {"error": {"message": "Supply the local Veil token in X-Veil-Token"}})
                return False
            if self.path in {"/healthz", "/readyz"}:
                return True
            accounts = self.headers.get_all("ChatGPT-Account-ID", [])
            if len(authorization) != 1 or api_keys or not re.fullmatch(r"Bearer [A-Za-z0-9._~+/-]+=*", authorization[0]) or len(authorization[0]) > 16384 or len(accounts) != 1 or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", accounts[0]):
                self.reply(401, {"error": {"message": "Codex ChatGPT bearer and account ID are required"}})
                return False
            self.chatgpt_account = accounts[0]
            return True
        if len(authorization) + len(api_keys) != 1:
            self.reply(401, {"error": {"message": "Supply the local Veil token as Bearer auth or x-api-key"}})
            return False
        provided = authorization[0].removeprefix("Bearer ") if authorization else api_keys[0]
        if not hmac.compare_digest(provided.encode(), self.server.token.encode()):
            self.reply(401, {"error": {"message": "Invalid local Veil token"}})
            return False
        return True

    def provider_headers(self, session: MaskingSession, path: str) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
        if self.server.codex_chatgpt:
            headers["Authorization"] = self.headers["Authorization"]
            headers["ChatGPT-Account-ID"] = self.chatgpt_account
            headers["originator"] = "codex_cli_rs"
            fedramp = self.headers.get_all("X-OpenAI-Fedramp", [])
            if fedramp:
                if len(fedramp) != 1 or fedramp[0] not in {"true", "false"}:
                    raise PolicyError("Invalid ChatGPT routing header")
                headers["X-OpenAI-Fedramp"] = fedramp[0]
        elif path.startswith("/v1/messages"):
            headers["x-api-key"] = self.server.api_key
            headers["anthropic-version"] = self.headers.get("anthropic-version", "2023-06-01")
        else:
            headers["Authorization"] = "Bearer " + self.server.api_key
        for name in ("anthropic-version", "anthropic-beta", "openai-beta"):
            values = self.headers.get_all(name, [])
            if len(values) > 1:
                raise PolicyError("Duplicate provider headers are blocked")
            if values:
                value = values[0]
                if len(value) > 4096 or find_candidates(value, self.server.rules, self.server.keywords) or session.mask(value) != value:
                    raise PolicyError("Sensitive or oversized provider headers are blocked")
                headers[name] = value
        return headers

    def do_GET(self) -> None:
        if not self.authorize():
            return
        if self.path in {"/healthz", "/readyz"}:
            self.reply(200, {"status": "ok", "mode": "enforce", "failure_policy": "closed"})
        elif self.path == "/v1/models" and not self.server.codex_chatgpt:
            self.forward(None, MaskingSession(self.server.rules, self.server.keywords))
        elif self.server.codex_chatgpt and re.fullmatch(r"/v1/models(?:\?client_version=[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})?", self.path):
            self.forward(None, MaskingSession(self.server.rules, self.server.keywords))
        else:
            self.reply(404, {"error": {"message": "Unsupported path; no request was forwarded"}})

    def do_POST(self) -> None:
        if not self.authorize():
            return
        if self.path == "/v1/messages?beta=true":
            self.path = "/v1/messages"
        if self.path not in REQUEST_FIELDS:
            self.reply(404, {"error": {"message": "Unsupported path; no request was forwarded"}})
            return
        if self.server.codex_chatgpt and self.path != "/v1/responses":
            self.reply(404, {"error": {"message": "ChatGPT subscription mode accepts only Responses requests"}})
            return
        if self.headers.get_content_type() != "application/json" or self.headers.get("Content-Encoding", "identity") != "identity":
            self.reply(415, {"error": {"message": "Uncompressed application/json required"}})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if self.headers.get("Transfer-Encoding") or len(lengths) != 1:
            self.reply(400, {"error": {"message": "One Content-Length header is required; chunked requests are blocked"}})
            return
        try:
            length = int(lengths[0])
            if length <= 0 or length > MAX_BODY:
                self.reply(413, {"error": {"message": "Request must be between 1 byte and 8 MiB"}})
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise PolicyError("Truncated request body")
            session = MaskingSession(self.server.rules, self.server.keywords)
            trusted = (lambda content: self.server.reasoning.check(self.chatgpt_account, content)) if self.server.codex_chatgpt else None
            payload = mask_request(self.path, json_loads(raw), session, trusted_reasoning=trusted)
            self.stream_requested = payload.get("stream", False)
            self.forward(json_bytes(payload), session)
        except PolicyError as error:
            self.reply(422, {"error": {"type": "veil_policy_error", "message": str(error)}})
        except (socket.timeout, OSError):
            if not self.sent_headers:
                self.reply(408, {"error": {"message": "Request timed out or connection failed"}})
        except Exception:
            if not self.sent_headers:
                self.reply(500, {"error": {"message": "Veil could not inspect the request; nothing further was forwarded"}})

    def forward(self, body: bytes | None, session: MaskingSession) -> None:
        connection = None
        try:
            headers = self.provider_headers(session, self.path)
        except PolicyError as error:
            self.reply(422, {"error": {"type": "veil_policy_error", "message": str(error)}})
            return
        try:
            connection, path = self.server.connect(self.path)
            connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                # Provider error text can echo request content or credentials.
                self.reply(response.status if 400 <= response.status < 600 else 502, {"error": {"type": "veil_upstream_error", "message": "Provider rejected the request; response details withheld", "status": response.status}})
                return
            content_type = response.getheader("Content-Type", "").split(";")[0].strip().lower()
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise PolicyError("Compressed provider responses are not supported")
            if content_type == "text/event-stream" or self.server.codex_chatgpt and not content_type and getattr(self, "stream_requested", False):
                self.stream_response(response, session)
            elif content_type == "application/json":
                raw = response.read(MAX_RESPONSE + 1)
                if len(raw) > MAX_RESPONSE:
                    raise PolicyError("Provider response exceeds 16 MiB")
                parsed = json_loads(raw)
                if self.server.codex_chatgpt:
                    self.server.reasoning.observe(self.chatgpt_account, parsed)
                payload = restore_response(parsed, session.mapping)
                self.reply(response.status, payload)
            else:
                raise PolicyError("Unsupported provider response content type")
        except (PolicyError, OSError, http.client.HTTPException, ValueError):
            if not self.sent_headers:
                self.reply(502, {"error": {"message": "Provider response could not be processed safely"}})
            else:
                self.close_connection = True
                try:
                    self.wfile.write(b'event: error\ndata: {"type":"error","error":{"type":"veil_stream_error","message":"Provider stream failed validation or ended early"}}\n\n')
                    self.wfile.flush()
                except OSError:
                    pass
        finally:
            if connection is not None:
                connection.close()

    def stream_response(self, response: http.client.HTTPResponse, session: MaskingSession) -> None:
        observer = (lambda value: self.server.reasoning.observe(self.chatgpt_account, value)) if self.server.codex_chatgpt else None
        processor = SSEProcessor(self.path, session.mapping, observer=observer)
        self.close_connection = True
        event = bytearray()
        while True:
            line = response.readline(MAX_EVENT + 1)
            if not line:
                if event:
                    raise PolicyError("Truncated SSE frame")
                processor.finish()
                return
            event.extend(line)
            if len(event) > MAX_EVENT:
                raise PolicyError("SSE event exceeds 1 MiB")
            if line in {b"\n", b"\r\n"}:
                processed = processor.process(bytes(event))
                if not self.sent_headers:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.sent_headers = True
                self.wfile.write(processed)
                self.wfile.flush()
                event.clear()


def local_token(path: Path) -> str:
    token = os.environ.get("VEIL_PROXY_TOKEN")
    if token:
        return token
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return path.read_text(encoding="utf-8").strip()
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        token = secrets.token_urlsafe(32)
        file.write(token + "\n")
    return token


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Veil: local fail-closed LLM privacy proxy (text and local tools)")
    parser.add_argument("--upstream", help="Provider base URL, e.g. https://api.anthropic.com (or VEIL_UPSTREAM_BASE_URL)")
    parser.add_argument("--codex-chatgpt", action="store_true", help="Forward Codex ChatGPT sign-in to the fixed subscription service; no upstream API key needed")
    parser.add_argument("--port", type=int, default=8765, help="Loopback port (default: 8765)")
    parser.add_argument("--timeout", type=float, default=120, help="Provider idle timeout in seconds (default: 120)")
    parser.add_argument("--token-file", type=Path, default=CONFIG_DIR / "proxy_token", help="Local token file; VEIL_PROXY_TOKEN overrides it")
    args = parser.parse_args(argv)
    upstream = args.upstream or (CHATGPT_UPSTREAM if args.codex_chatgpt else os.environ.get("VEIL_UPSTREAM_BASE_URL"))
    api_key = "" if args.codex_chatgpt else os.environ.get("VEIL_UPSTREAM_API_KEY", "")
    if not upstream or not args.codex_chatgpt and not api_key:
        parser.error("Set --upstream (or VEIL_UPSTREAM_BASE_URL) and VEIL_UPSTREAM_API_KEY")
    if not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535")
    try:
        server = ProxyServer(("127.0.0.1", args.port), upstream, api_key, local_token(args.token_file), load_rules(), load_user_keywords(), args.timeout, codex_chatgpt=args.codex_chatgpt)
    except (OSError, ValueError):
        parser.error("Cannot start: check the base URL, credentials, rules, timeout and available port")
    print(f"Veil proxy: http://127.0.0.1:{args.port} (fail-closed; text-only; mappings in memory)")
    print(f"Client credential: VEIL_PROXY_TOKEN or local file {args.token_file}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
