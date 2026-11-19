"""Synthetic regression tests; never call an external model."""

import http.client
import io
import json
import re
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from anonymize import _keyword_pattern, anonymize, find_candidates, load_rules, restore
from veil_protocol import MaskingSession, PolicyError, SSEProcessor, StreamRestorer, json_bytes, json_loads, mask_request
from veil_proxy import ProxyServer, ReasoningCache


RULES = load_rules()
EMPTY_KEYWORDS = {"entries": (), "ignored": set()}


def packet(payload):
    return b"data: " + json_bytes(payload) + b"\n\n"


def event_values(output):
    return [json.loads(line[6:]) for line in output.splitlines() if line.startswith(b"data: ") and line != b"data: [DONE]"]


class DetectionTests(unittest.TestCase):
    def test_unicode_restores_exact_original(self):
        source = "ФИО: Иванов\u00a0Иван; test@example.com"
        masked, mapping, _, _ = anonymize(source, RULES, auto=True)
        self.assertEqual(restore(masked, mapping), source)

    def test_overlap_masks_union(self):
        rules = [{"name": "first", "type": "SECRET", "regex": "abcde"}, {"name": "second", "type": "SECRET", "regex": "defgh"}]
        masked, mapping, _, _ = anonymize("abcdefgh", rules, auto=True)
        self.assertEqual(masked, "{{SECRET_1}}")
        self.assertEqual(restore(masked, mapping), "abcdefgh")

    def test_existing_placeholder_and_nonrecursive_restore(self):
        masked, mapping, _, _ = anonymize("{{EMAIL_1}} test@example.com", RULES, auto=True)
        self.assertIn("{{EMAIL_2}}", masked)
        self.assertEqual(restore(masked, mapping), "{{EMAIL_1}} test@example.com")
        self.assertEqual(restore("{{A}} {{B}}", {"{{A}}": "{{B}}", "{{B}}": "secret"}), "{{B}} secret")

    def test_secrets_and_cards(self):
        samples = ["sk-proj-" + "a" * 32, "ghp_" + "b" * 36, "AKIA" + "A" * 16,
                   "Bearer abcdefghijklmnop", "password=small", "4111 1111 1111 1111",
                   "-----BEGIN PRIVATE KEY-----\nsynthetic\n-----END PRIVATE KEY-----"]
        for source in samples:
            with self.subTest(source=source[:12]):
                masked, mapping, count, _ = anonymize(source, RULES, auto=True)
                self.assertGreater(count, 0)
                self.assertNotEqual(masked, source)
                self.assertEqual(restore(masked, mapping), source)
        self.assertNotIn("CARD", {candidate["type"] for candidate in find_candidates("4111 1111 1111 1112", RULES)})

    def test_existing_hard_test_spec(self):
        spec = json.loads((Path(__file__).parent / "hard_test_spec.json").read_text(encoding="utf-8"))
        for item in spec["positive"]:
            with self.subTest(text=item["text"]):
                source = item.get("context", item["text"])
                masked, _, _, _ = anonymize(source, RULES, auto=True)
                self.assertNotIn(item["text"], masked)
        for source in spec["negative"]:
            self.assertEqual(anonymize(source, RULES, auto=True)[0], source)

    def test_long_identifier_finishes_without_quadratic_backtracking(self):
        command = [sys.executable, "-c", "from anonymize import find_candidates, load_rules; rules=load_rules(); samples=['a'*100000,'A'*100000,'aA'*50000,chr(0x410)*100000,'token'+'-'*100000,'+'*100000]; assert all(not find_candidates(source, rules) for source in samples)"]
        result = subprocess.run(command, cwd=Path(__file__).resolve().parents[1], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


class ProtocolTests(unittest.TestCase):
    def session(self):
        return MaskingSession(RULES, EMPTY_KEYWORDS)

    def test_shared_mapping_and_isolation(self):
        session = self.session()
        a = session.mask("test@example.com")
        b = session.mask("test@example.com other@example.com")
        self.assertTrue(b.startswith(a))
        self.assertEqual(len(session.mapping), 2)
        self.assertNotEqual(a, self.session().mask("test@example.com"))

    def test_nested_tool_arguments_decode_unicode(self):
        for path, payload in [
            ("/v1/chat/completions", {"model": "mock", "messages": [{"role": "assistant", "tool_calls": [{"type": "function", "id": "call_1", "function": {"name": "lookup", "arguments": '{"email":"test\\u0040example.com","password":"abc"}'}}]}]}),
            ("/v1/responses", {"model": "mock", "input": [{"type": "function_call", "call_id": "call_1", "name": "lookup", "arguments": '{"email":"test\\u0040example.com","password":"abc"}'}]}),
        ]:
            with self.subTest(path=path):
                session = self.session()
                result = json_bytes(mask_request(path, payload, session))
                self.assertNotIn(b"example.com", result)
                self.assertNotIn(b'"abc"', result)
                self.assertIn("test@example.com", session.mapping.values())
                self.assertIn("abc", session.mapping.values())

    def test_opaque_inputs_and_state_rejected(self):
        cases = [
            ("/v1/responses", {"input": [{"type": "message", "content": [{"type": "input_file", "file_data": "sensitive"}]}]}),
            ("/v1/responses", {"input": "hello", "previous_response_id": "resp_123"}),
            ("/v1/responses", {"input": "hello", "store": True}),
            ("/v1/responses", {"input": "hello", "background": True}),
            ("/v1/responses", {"input": "hello", "unknown": "secret"}),
            ("/v1/messages", {"messages": [{"role": "user", "content": [{"type": "image", "source": {"data": "secret"}}]}]}),
            ("/v1/messages", {"messages": [{"role": "user", "content": "hi"}], "tools": [{"type": "web_search_20250305", "name": "web_search"}]}),
        ]
        for path, payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(PolicyError):
                    mask_request(path, {"model": "mock", **payload}, self.session())

    def test_sensitive_numbers_blocked(self):
        with self.assertRaises(PolicyError):
            mask_request("/v1/messages", {"model": "mock", "messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "call_1", "name": "lookup", "input": {"phone": 79991234567}}]}]}, self.session())

    def test_duplicate_keys_rejected(self):
        for raw in ['{"input":"safe","input":"secret"}', '{"n":NaN}']:
            with self.assertRaises(PolicyError):
                json_loads(raw)

    def test_known_secret_is_masked_everywhere_independent_of_field_order(self):
        for credential_key in ("password", "token", "refresh_token", "aws_secret_access_key"):
            for reverse in (False, True):
                pairs = [("model", "mock"), ("input", "Use opaqueShortSecret again: opaqueShortSecret"), ("metadata", {credential_key: "opaqueShortSecret"})]
                payload = dict(reversed(pairs) if reverse else pairs)
                session = self.session()
                masked = mask_request("/v1/responses", payload, session)
                self.assertNotIn(b"opaqueShortSecret", json_bytes(masked))
                self.assertEqual(len(session.mapping), 1)

    def test_credential_schema_and_namespace_tools_are_preserved(self):
        schema = {"type": "object", "properties": {"password": {"type": "string"}, "refresh_token": {"type": "string"}}}
        for path, payload in [
            ("/v1/messages", {"messages": [{"role": "user", "content": "hello"}], "tools": [{"name": "save", "input_schema": schema}]}),
            ("/v1/responses", {"input": "hello", "tools": [{"type": "namespace", "name": "local", "tools": [{"type": "function", "name": "save", "parameters": schema}]}]}),
        ]:
            result = mask_request(path, {"model": "mock", **payload}, self.session())
            self.assertEqual(result["tools"], payload["tools"])

    def test_sse_terminal_events_required_and_post_terminal_data_rejected(self):
        cases = [
            ("/v1/chat/completions", {"choices": [{"index": 0, "delta": {"content": "partial"}}]}, {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
            ("/v1/messages", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "partial"}}, {"type": "message_stop"}),
            ("/v1/responses", {"type": "response.output_text.delta", "output_index": 0, "delta": "partial"}, {"type": "response.completed", "response": {}}),
        ]
        for path, delta, terminal in cases:
            processor = SSEProcessor(path, {})
            processor.process(packet(delta))
            with self.assertRaises(PolicyError):
                processor.finish()
            processor.process(packet(terminal))
            processor.finish()
            with self.assertRaises(PolicyError):
                processor.process(packet(delta))

    def test_custom_tool_input_deltas_restore_without_json_escaping(self):
        token = "{{VEIL_test_SECRET_1}}"
        original = 'Пример "quote" \\path\nline'
        processor = SSEProcessor("/v1/responses", {token: original})
        output = b"".join(processor.process(packet({"type": "response.custom_tool_call_input.delta", "output_index": 0, "delta": char})) for char in token)
        output += processor.process(packet({"type": "response.completed", "response": {}}))
        processor.finish()
        self.assertEqual("".join(value.get("delta", "") for value in event_values(output)), original)

    def test_every_token_boundary_and_json_escape(self):
        token = "{{VEIL_test_PERSON_1}}"
        original = 'Тест "quote" \\path\nline'
        for index in range(len(token) + 1):
            stream = StreamRestorer({token: original})
            self.assertEqual(stream.feed("prefix " + token[:index]) + stream.feed(token[index:] + " suffix", True), "prefix " + original + " suffix")
        stream = StreamRestorer({token: original}, json_fragment=True)
        output = "".join(stream.feed(char) for char in '{"value":"' + token + '"}') + stream.feed("", True)
        self.assertEqual(json.loads(output)["value"], original)

    def test_parallel_chat_choices_and_tools(self):
        token = "{{VEIL_test_EMAIL_1}}"
        processor = SSEProcessor("/v1/chat/completions", {token: 'a"b@example.com'})
        frames = []
        for char in token:
            frames.append(processor.process(packet({"choices": [{"index": 0, "delta": {"content": char}}, {"index": 1, "delta": {"content": char}}]})))
        self.assertEqual(["".join(event["choices"][i]["delta"]["content"] for frame in frames for event in event_values(frame)) for i in (0, 1)], ['a"b@example.com'] * 2)

    def test_pending_literal_flushes_before_finish(self):
        for path, start, stop, field in [
            ("/v1/chat/completions", {"choices": [{"index": 0, "delta": {"content": "ends {"}}]}, {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}, "content"),
            ("/v1/messages", {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "ends {"}}, {"type": "content_block_stop", "index": 0}, "text"),
            ("/v1/responses", {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "ends {"}, {"type": "response.completed", "response": {}}, "delta"),
        ]:
            processor = SSEProcessor(path, {"{{VEIL_test_EMAIL_1}}": "a@example.com"})
            output = processor.process(packet(start)) + processor.process(packet(stop))
            values = event_values(output)
            if path == "/v1/chat/completions":
                text = "".join(v["choices"][0]["delta"].get(field, "") for v in values)
            elif path == "/v1/messages":
                text = "".join(v.get("delta", {}).get(field, "") for v in values)
            else:
                text = "".join(v.get(field, "") for v in values if isinstance(v.get(field), str))
            self.assertEqual(text, "ends {")


class MockProvider(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_header(self, keyword, value):
        if keyword.lower() == "content-type" and getattr(self.server, "omit_content_type", False):
            return
        super().send_header(keyword, value)

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json_bytes({"object": "list", "data": [{"id": "mock", "object": "model"}]}))

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        self.server.requests.append((self.path, raw, dict(self.headers)))
        payload = json.loads(raw)
        if payload["model"] == "mock-error":
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"PRIVATE PROVIDER CREDENTIAL"}')
            return
        tokens = list(dict.fromkeys(re.findall(r"\{\{VEIL_[A-Za-z0-9_]+\}\}", raw.decode())))
        text = " | ".join(tokens) + " привет"
        arguments = json.dumps({"value": text}, ensure_ascii=False)
        streaming = payload.get("stream", False)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if streaming else "application/json")
        self.end_headers()
        if not streaming:
            if self.path.endswith("/messages"):
                response = {"content": [{"type": "text", "text": text}, {"type": "tool_use", "id": "call_1", "name": "write", "input": {"value": text}}]}
            elif self.path.endswith("/responses"):
                response = {"output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}, {"type": "function_call", "name": "write", "arguments": arguments}]}
            else:
                response = {"choices": [{"message": {"content": text, "tool_calls": [{"function": {"name": "write", "arguments": arguments}}]}}]}
            self.wfile.write(json_bytes(response))
            return
        frames = []
        if self.path.endswith("/messages"):
            frames.append({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
            frames.extend({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": char}} for char in text)
            frames.append({"type": "content_block_stop", "index": 0})
            frames.append({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "call_1", "name": "write", "input": {}}})
            frames.extend({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": char}} for char in arguments)
            frames.extend([{"type": "content_block_stop", "index": 1}, {"type": "message_stop"}])
        elif self.path.endswith("/responses"):
            frames.extend({"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": char} for char in text)
            frames.extend({"type": "response.function_call_arguments.delta", "output_index": 1, "item_id": "call_1", "delta": char} for char in arguments)
            frames.append({"type": "response.completed", "response": {"status": "completed"}})
        else:
            frames.extend({"id": "chat_1", "choices": [{"index": 0, "delta": {"content": char}, "finish_reason": None}]} for char in text)
            frames.extend({"id": "chat_1", "choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "function": {"arguments": char}}]}, "finish_reason": None}]} for char in arguments)
            frames.append({"id": "chat_1", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]})
        wire = b"".join(packet(frame) for frame in frames)
        for index in range(0, len(wire), 37):
            self.wfile.write(wire[index:index + 37])
        self.wfile.flush()


class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = ThreadingHTTPServer(("127.0.0.1", 0), MockProvider)
        cls.provider.requests = []
        keyword = 'Проект "Север" \\секрет'
        keywords = {"entries": ({"type": "SENSITIVE", "keyword": keyword, "patterns": (_keyword_pattern(keyword),)},), "ignored": set()}
        cls.original = keyword
        cls.proxy = ProxyServer(("127.0.0.1", 0), f"http://127.0.0.1:{cls.provider.server_port}/v1", "synthetic-provider-key", "synthetic-local-token", RULES, keywords, timeout=3)
        cls.threads = [threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True) for server in (cls.provider, cls.proxy)]
        for thread in cls.threads:
            thread.start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.proxy, cls.provider):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=2)

    def request(self, path, payload=None, headers=None, method="POST"):
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=5)
        auth = {"Authorization": "Bearer synthetic-local-token", "Content-Type": "application/json"}
        if headers:
            auth.update(headers)
        body = json_bytes(payload) if payload is not None else None
        connection.request(method, path, body=body, headers=auth)
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def payload(self, path, stream=False):
        text = self.original + " test@example.com"
        return {"model": "mock", "stream": stream, **({"input": text} if path == "/v1/responses" else {"messages": [{"role": "user", "content": text}]})}

    def test_json_and_sse_roundtrip_all_apis(self):
        for path in ("/v1/chat/completions", "/v1/responses", "/v1/messages"):
            for stream in (False, True):
                with self.subTest(path=path, stream=stream):
                    status, raw = self.request(path, self.payload(path, stream))
                    self.assertEqual(status, 200, raw)
                    _, forwarded, headers = self.provider.requests[-1]
                    self.assertNotIn(b"example.com", forwarded)
                    self.assertNotIn(self.original.encode(), forwarded)
                    self.assertNotIn("synthetic-local-token", str(headers))
                    self.assertNotIn("{{VEIL_", raw.decode())
                    if stream:
                        events = event_values(raw)
                        if path == "/v1/chat/completions":
                            text = "".join(v["choices"][0]["delta"].get("content", "") for v in events)
                            args = "".join(tool["function"].get("arguments", "") for v in events for tool in v["choices"][0]["delta"].get("tool_calls", []))
                        elif path == "/v1/messages":
                            text = "".join(v.get("delta", {}).get("text", "") for v in events)
                            args = "".join(v.get("delta", {}).get("partial_json", "") for v in events)
                        else:
                            text = "".join(v.get("delta", "") for v in events if v["type"] == "response.output_text.delta")
                            args = "".join(v.get("delta", "") for v in events if v["type"] == "response.function_call_arguments.delta")
                    else:
                        result = json.loads(raw)
                        if path == "/v1/chat/completions":
                            text = result["choices"][0]["message"]["content"]
                            args = result["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
                        elif path == "/v1/messages":
                            text = result["content"][0]["text"]
                            args = json.dumps(result["content"][1]["input"])
                        else:
                            text = result["output"][0]["content"][0]["text"]
                            args = result["output"][1]["arguments"]
                    self.assertIn(self.original, text)
                    self.assertIn("test@example.com", text)
                    self.assertEqual(json.loads(args)["value"], text)

    def test_local_document_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "synthetic.txt"
            source.write_text(self.original, encoding="utf-8")
            before = source.read_bytes()
            self.request("/v1/responses", {"model": "mock", "input": source.read_text(encoding="utf-8")})
            self.assertEqual(source.read_bytes(), before)

    def test_rejections_never_reach_provider(self):
        before = len(self.provider.requests)
        cases = [
            ("/v1/files", {"model": "mock", "input": "secret"}, None),
            ("/v1/responses", {"model": "mock", "input": [{"type": "input_image", "image_url": "secret"}]}, None),
            ("/v1/responses", {"model": "mock", "input": "secret", "unknown": "secret"}, None),
            ("/v1/responses", {"model": "mock", "input": "secret"}, {"Origin": "https://evil.example"}),
            ("/v1/responses", {"model": "mock", "input": "secret"}, {"Authorization": "Bearer wrong"}),
        ]
        for path, payload, headers in cases:
            status, _ = self.request(path, payload, headers)
            self.assertGreaterEqual(status, 400)
        self.assertEqual(len(self.provider.requests), before)

    def test_masking_failure_never_reaches_provider(self):
        before = len(self.provider.requests)
        with patch("veil_protocol.find_candidates", side_effect=RuntimeError("PRIVATE INPUT")):
            status, body = self.request("/v1/responses", self.payload("/v1/responses"))
        self.assertEqual(status, 500)
        self.assertNotIn(b"PRIVATE INPUT", body)
        self.assertEqual(len(self.provider.requests), before)

    def test_known_credential_does_not_reach_provider_in_other_fields(self):
        status, _ = self.request("/v1/responses", {"model": "mock", "input": "Repeat opaqueShortSecret", "metadata": {"password": "opaqueShortSecret"}})
        self.assertEqual(status, 200)
        self.assertNotIn(b"opaqueShortSecret", self.provider.requests[-1][1])

    def test_sensitive_provider_headers_are_blocked_independently_of_body(self):
        before = len(self.provider.requests)
        for name in ("anthropic-beta", "anthropic-version", "openai-beta"):
            status, _ = self.request("/v1/responses", {"model": "mock", "input": "hello"}, {name: "test@example.com"})
            self.assertEqual(status, 422)
        self.assertEqual(len(self.provider.requests), before)

    def test_provider_errors_and_headers_are_not_relayed(self):
        status, raw = self.request("/v1/responses", {"model": "mock-error", "input": "hi"})
        self.assertEqual(status, 429)
        self.assertNotIn(b"PRIVATE PROVIDER CREDENTIAL", raw)

    def test_models_and_health(self):
        self.assertEqual(self.request("/healthz", method="GET")[0], 200)
        status, raw = self.request("/v1/models", method="GET")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["data"][0]["id"], "mock")

    def test_concurrent_request_mapping_isolation(self):
        def send(index):
            email = f"person{index}@example.com"
            status, body = self.request("/v1/responses", {"model": "mock", "input": email})
            self.assertEqual(status, 200)
            text = json.loads(body)["output"][0]["content"][0]["text"]
            self.assertEqual(text, email + " привет")
        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(send, range(8)))

    def test_upstream_https_required(self):
        with self.assertRaises(ValueError):
            ProxyServer(("127.0.0.1", 0), "http://external.example", "key", "token", RULES, EMPTY_KEYWORDS)


class ChatGPTTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = ThreadingHTTPServer(("127.0.0.1", 0), MockProvider)
        cls.provider.requests = []
        cls.proxy = ProxyServer(("127.0.0.1", 0), f"http://127.0.0.1:{cls.provider.server_port}/backend-api/codex", "", "synthetic-local-token", RULES, EMPTY_KEYWORDS, timeout=3, codex_chatgpt=True)
        cls.threads = [threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True) for server in (cls.provider, cls.proxy)]
        for thread in cls.threads:
            thread.start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.proxy, cls.provider):
            server.shutdown()
            server.server_close()
        for thread in cls.threads:
            thread.join(timeout=2)

    def request(self, payload, headers=None, path="/v1/responses", method="POST"):
        auth = {"Authorization": "Bearer synthetic-subscription-session", "ChatGPT-Account-ID": "account-synthetic", "X-Veil-Token": "synthetic-local-token", "Content-Type": "application/json"}
        auth.update(headers or {})
        auth = {key: value for key, value in auth.items() if value is not None}
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=5)
        connection.request(method, path, body=json_bytes(payload) if payload is not None else None, headers=auth)
        response = connection.getresponse()
        status, body = response.status, response.read()
        connection.close()
        return status, body

    def test_subscription_auth_routing_and_restoration_json_and_sse(self):
        for stream in (False, True):
            status, body = self.request({"model": "mock", "input": "test@example.com", "stream": stream})
            self.assertEqual(status, 200, body)
            path, raw, headers = self.provider.requests[-1]
            self.assertEqual(path, "/backend-api/codex/responses")
            self.assertEqual(headers["Authorization"], "Bearer synthetic-subscription-session")
            self.assertEqual(headers["ChatGPT-Account-ID"], "account-synthetic")
            self.assertNotIn("X-Veil-Token", headers)
            self.assertNotIn(b"test@example.com", raw)
            if not stream:
                self.assertIn("test@example.com", json.loads(body)["output"][0]["content"][0]["text"])

    def test_missing_duplicate_or_wrong_credentials_never_forward(self):
        before = len(self.provider.requests)
        for headers in ({"X-Veil-Token": None}, {"X-Veil-Token": "wrong"}, {"Authorization": None}, {"ChatGPT-Account-ID": None}, {"x-api-key": "unexpected"}, {"Authorization": "not-a-bearer"}):
            self.assertEqual(self.request({"model": "mock", "input": "hello"}, headers)[0], 403 if "X-Veil-Token" in headers else 401)
        self.assertEqual(len(self.provider.requests), before)

    def test_refresh_stays_in_codex_new_bearer_is_forwarded_per_request(self):
        for bearer in ("old-session", "new-session"):
            status, _ = self.request({"model": "mock", "input": "hello"}, {"Authorization": "Bearer " + bearer})
            self.assertEqual(status, 200)
            self.assertEqual(self.provider.requests[-1][2]["Authorization"], "Bearer " + bearer)
        self.assertEqual(self.request({"model": "mock-error", "input": "hello"})[0], 429)

    def test_subscription_destination_is_pinned(self):
        for upstream in ("https://evil.example/backend-api/codex", "https://chatgpt.com.evil.example/backend-api/codex", "https://api.openai.com/v1", "https://chatgpt.com/other", "https://chatgpt.com/backend-api/codex?redirect=evil"):
            with self.assertRaises(ValueError):
                ProxyServer(("127.0.0.1", 0), upstream, "", "token", RULES, EMPTY_KEYWORDS, codex_chatgpt=True)

    def test_health_needs_only_local_credential_and_other_apis_are_blocked(self):
        self.assertEqual(self.request(None, {"Authorization": None, "ChatGPT-Account-ID": None}, path="/healthz", method="GET")[0], 200)
        before = len(self.provider.requests)
        self.assertEqual(self.request({"model": "mock", "messages": [{"role": "user", "content": "hello"}]}, path="/v1/messages")[0], 404)
        self.assertEqual(len(self.provider.requests), before)
        self.assertEqual(self.request(None, path="/v1/models?client_version=0.165.0", method="GET")[0], 200)
        self.assertEqual(self.request(None, path="/v1/models?secret=private", method="GET")[0], 404)

    def test_reasoning_is_account_bound_bounded_and_expires(self):
        cache = ReasoningCache()
        value = {"output": [{"type": "reasoning", "encrypted_content": "synthetic-ciphertext"}]}
        cache.observe("account-a", value)
        self.assertTrue(cache.check("account-a", "synthetic-ciphertext"))
        self.assertFalse(cache.check("account-b", "synthetic-ciphertext"))
        cache.observe("account-a", {"metadata": {"type": "reasoning", "encrypted_content": "untrusted"}})
        self.assertFalse(cache.check("account-a", "untrusted"))
        expiring = ReasoningCache()
        with patch("veil_proxy.time.monotonic", return_value=1):
            expiring.check("account-a", "expired", remember=True)
        with patch("veil_proxy.time.monotonic", return_value=1802):
            self.assertFalse(expiring.check("account-a", "expired"))
        for index in range(1100):
            cache.check("account-a", str(index), remember=True)
        self.assertLessEqual(len(cache.entries), 1024)

    def test_only_observed_reasoning_can_be_replayed(self):
        cipher = "opaque-synthetic-ciphertext"
        reasoning = {"type": "reasoning", "id": "rs_1", "summary": [], "encrypted_content": cipher}
        payload = {"model": "mock", "input": [reasoning, {"role": "user", "content": "test@example.com"}], "include": ["reasoning.encrypted_content"]}
        before = len(self.provider.requests)
        self.assertEqual(self.request(payload)[0], 422)
        self.assertEqual(len(self.provider.requests), before)
        self.proxy.reasoning.observe("account-synthetic", {"type": "response.output_item.done", "item": reasoning})
        self.assertEqual(self.request(payload)[0], 200)
        sent = json.loads(self.provider.requests[-1][1])
        self.assertEqual(sent["input"][0]["encrypted_content"], cipher)
        self.assertEqual(sent["include"], ["reasoning.encrypted_content"])
        self.assertNotIn(b"test@example.com", self.provider.requests[-1][1])
        self.assertEqual(self.request(payload, {"ChatGPT-Account-ID": "other-account"})[0], 422)

    def test_sse_observes_original_upstream_reasoning(self):
        cache = ReasoningCache()
        processor = SSEProcessor("/v1/responses", {}, observer=lambda value: cache.observe("account", value))
        processor.process(packet({"type": "response.output_item.done", "item": {"type": "reasoning", "encrypted_content": "cipher-from-sse"}}))
        self.assertTrue(cache.check("account", "cipher-from-sse"))
        with self.assertRaises(PolicyError):
            processor.process(packet({"output": [{"type": "reasoning", "encrypted_content": "untyped-frame"}]}))

    def test_reasoning_preserves_previous_turn_restoration_json_and_sse(self):
        for streaming in (False, True):
            with self.subTest(streaming=streaming):
                old_tokens = []
                reasoning = {"type": "reasoning", "summary": [], "encrypted_content": f"history-cipher-{streaming}"}

                def respond(handler):
                    raw = handler.rfile.read(int(handler.headers["Content-Length"]))
                    self.assertNotIn(b"test@example.com", raw)
                    self.assertNotIn(b"opaqueShortSecret", raw)
                    if not old_tokens:
                        old_tokens.extend(re.findall(r"\{\{VEIL_[A-Za-z0-9_]+\}\}", raw.decode()))
                    text = " | ".join(dict.fromkeys(old_tokens))
                    output = [reasoning, {"type": "message", "content": [{"type": "output_text", "text": text}]},
                              {"type": "function_call", "name": "write", "arguments": json.dumps({"value": text})}]
                    handler.send_response(200)
                    handler.send_header("Content-Type", "text/event-stream" if streaming else "application/json")
                    handler.end_headers()
                    response = {"output": output, "status": "completed"}
                    handler.wfile.write(packet({"type": "response.completed", "response": response}) if streaming else json_bytes(response))

                with patch.object(MockProvider, "do_POST", respond):
                    first = {"model": "mock", "input": "test@example.com", "metadata": {"password": "opaqueShortSecret"}, "stream": streaming}
                    self.assertEqual(self.request(first)[0], 200)
                    # The second reply deliberately uses only the first turn's tokens.
                    second = {"model": "mock", "input": [reasoning, {"role": "user", "content": "Repeat opaqueShortSecret"}], "stream": streaming}
                    status, body = self.request(second)
                    self.assertEqual(status, 200, body)
                    response = event_values(body)[0]["response"] if streaming else json.loads(body)
                    text = response["output"][1]["content"][0]["text"]
                    self.assertIn("test@example.com", text)
                    self.assertIn("opaqueShortSecret", text)
                    self.assertNotIn("{{VEIL_", text)
                    self.assertEqual(json.loads(response["output"][2]["arguments"])["value"], text)

    def test_reasoning_mapping_snapshot_and_memory_budget(self):
        cache = ReasoningCache()
        session = MaskingSession(RULES, EMPTY_KEYWORDS)
        token = session.token("opaqueShortSecret")
        cache.check("a", "cipher", remember=True, session=session)
        session.mapping.clear()
        target = MaskingSession(RULES, EMPTY_KEYWORDS)
        self.assertTrue(cache.check("a", "cipher", session=target))
        self.assertEqual(target.mapping[token], "opaqueShortSecret")
        self.assertEqual(target.tokens["opaqueShortSecret"], token)
        other = MaskingSession(RULES, EMPTY_KEYWORDS)
        self.assertFalse(cache.check("b", "cipher", session=other))
        self.assertEqual(other.mapping, {})
        with patch.object(cache, "MAX_BYTES", 1600):
            self.assertTrue(cache.check("a", "new", remember=True, session=target))
            self.assertFalse(cache.check("a", "cipher"))
            target.mapping["extra"] = "x" * 1000
            self.assertFalse(cache.check("a", "oversized", remember=True, session=target))
            self.assertFalse(cache.check("a", "oversized"))
            self.assertLessEqual(cache.used_bytes, cache.MAX_BYTES)
        self.assertFalse(cache.check("account", "untyped-frame"))

    def test_subscription_sse_without_content_type_is_validated(self):
        self.provider.omit_content_type = True
        try:
            status, body = self.request({"model": "mock", "input": "test@example.com", "stream": True})
            self.assertEqual(status, 200, body)
            self.assertIn(b"response.completed", body)
        finally:
            self.provider.omit_content_type = False
        response = SimpleNamespace(status=200, getheader=lambda name, default=None: default, readline=io.BytesIO(b"<html>not an SSE response</html>\n\n").readline)
        connection = SimpleNamespace(request=lambda *args, **kwargs: None, getresponse=lambda: response, close=lambda: None)
        with patch.object(self.proxy, "connect", return_value=(connection, "/responses")):
            self.assertEqual(self.request({"model": "mock", "input": "hello", "stream": True})[0], 502)

    def test_responses_lite_text_and_tools_are_masked_and_unknown_opaque_is_blocked(self):
        payload = {"model": "mock", "input": [
            {"type": "additional_tools", "role": "developer", "tools": [{"type": "function", "name": "read", "parameters": {"type": "object", "properties": {"password": {"type": "string"}}}}]},
            {"type": "agent_message", "author": "user", "recipient": "assistant", "content": [{"type": "input_text", "text": "test@example.com"}]},
        ]}
        self.assertEqual(self.request(payload)[0], 200)
        self.assertNotIn(b"test@example.com", self.provider.requests[-1][1])
        payload["input"][0]["tools"][0]["type"] = "web_search"
        self.assertEqual(self.request(payload)[0], 422)
        payload["input"] = [{"type": "agent_message", "author": "user", "recipient": "assistant", "content": [{"type": "encrypted_content", "encrypted_content": "untrusted"}]}]
        self.assertEqual(self.request(payload)[0], 422)


if __name__ == "__main__":
    unittest.main()
