"""Text-only LLM payload masking and incremental response restoration."""

from __future__ import annotations

import json
import re
import secrets
from typing import Any

from anonymize import find_candidates


class PolicyError(ValueError):
    """A request cannot be inspected safely; it must not reach the provider."""


def json_loads(value: str | bytes) -> Any:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, item in pairs:
            if key in result:
                raise PolicyError("Duplicate JSON keys are not supported")
            result[key] = item
        return result

    def invalid_constant(_: str) -> None:
        raise PolicyError("Non-finite JSON numbers are not supported")

    try:
        return json.loads(value, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise PolicyError("Invalid JSON payload") from error


def json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


class MaskingSession:
    """One mapping for all fields of a request; originals never leave this object."""

    def __init__(self, rules: list[dict], keywords: dict | None = None):
        self.rules = rules
        self.keywords = keywords
        self.mapping: dict[str, str] = {}
        self.tokens: dict[str, str] = {}
        self.prefix = "{{VEIL_" + secrets.token_hex(8) + "_"

    def mask(self, text: str) -> str:
        if self.prefix in text:
            raise PolicyError("Placeholder namespace collision")
        changes = []
        for candidate in find_candidates(text, self.rules, self.keywords):
            value = text[candidate["start"]:candidate["end"]]
            token = self.token(value, candidate["type"])
            changes.append((candidate["start"], candidate["end"], token))
        for start, end, token in reversed(changes):
            text = text[:start] + token + text[end:]
        return text

    def token(self, value: str, entity_type: str = "SECRET") -> str:
        if value not in self.tokens:
            token = self.prefix + entity_type + "_" + str(len(self.mapping) + 1) + "}}"
            self.mapping[token] = value
            self.tokens[value] = token
        return self.tokens[value]


COMMON_FIELDS = {
    "model", "stream", "temperature", "top_p", "max_tokens", "stop", "tools", "tool_choice",
    "metadata", "user", "service_tier", "stream_options", "parallel_tool_calls",
}
REQUEST_FIELDS = {
    "/v1/chat/completions": COMMON_FIELDS | {
        "messages", "max_completion_tokens", "n", "seed", "frequency_penalty", "presence_penalty",
        "logprobs", "top_logprobs", "logit_bias", "response_format", "reasoning_effort",
        "store", "safety_identifier", "prompt_cache_key", "prompt_cache_retention", "verbosity",
    },
    "/v1/responses": COMMON_FIELDS | {
        "input", "instructions", "max_output_tokens", "reasoning", "text", "truncation", "include",
        "store", "background", "previous_response_id", "conversation", "max_tool_calls",
        "safety_identifier", "prompt_cache_key", "prompt_cache_retention", "top_logprobs",
        "client_metadata",
    },
    "/v1/messages": COMMON_FIELDS | {"messages", "system", "top_k", "stop_sequences", "thinking", "output_config"},
}
BLOCK_TYPES = {"text", "input_text", "output_text", "tool_use", "tool_result"}
SENSITIVE_KEYS = re.compile(r"(?i)^(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?token|authorization|пароль)$")


def _validate_content(content: Any) -> None:
    if isinstance(content, str):
        return
    if not isinstance(content, list):
        raise PolicyError("Only text content and text tool results are supported")
    for block in content:
        if not isinstance(block, dict) or block.get("type") not in BLOCK_TYPES:
            raise PolicyError("Images, files, audio, thinking and unknown content blocks are blocked; extract text locally")
        kind = block["type"]
        allowed = {
            "text": {"type", "text", "cache_control"},
            "input_text": {"type", "text"},
            "output_text": {"type", "text", "annotations"},
            "tool_use": {"type", "id", "name", "input"},
            "tool_result": {"type", "tool_use_id", "content", "is_error", "cache_control"},
        }[kind]
        if block.keys() - allowed:
            raise PolicyError("Unknown content block fields are blocked")
        if kind == "tool_result":
            _validate_content(block.get("content", ""))
        elif kind == "tool_use":
            if not isinstance(block.get("input"), dict):
                raise PolicyError("Tool input must be a JSON object")
        elif not isinstance(block.get("text"), str):
            raise PolicyError("Text blocks require a text string")


def _validate_messages(messages: Any) -> None:
    if not isinstance(messages, list) or not messages:
        raise PolicyError("A non-empty messages array is required")
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in {"system", "developer", "user", "assistant", "tool", "function"}:
            raise PolicyError("Unsupported message role or schema")
        if message.keys() - {"role", "content", "name", "tool_call_id", "tool_calls", "function_call", "refusal"}:
            raise PolicyError("Unknown message fields are blocked")
        if message.get("content") is not None:
            _validate_content(message["content"])
        elif not message.get("tool_calls") and not message.get("function_call"):
            raise PolicyError("Message content is required")


def mask_request(path: str, payload: Any, session: MaskingSession) -> dict:
    if path not in REQUEST_FIELDS or not isinstance(payload, dict):
        raise PolicyError("Unsupported API path or request object")
    if payload.keys() - REQUEST_FIELDS[path]:
        raise PolicyError("Unknown request fields are blocked; see docs/proxy.md for supported APIs")
    if not isinstance(payload.get("model"), str) or not payload["model"]:
        raise PolicyError("A model name is required")
    if "stream" in payload and not isinstance(payload["stream"], bool):
        raise PolicyError("stream must be a boolean")
    if payload.get("store") is True or payload.get("background") is True:
        raise PolicyError("Provider-side storage and background requests are blocked")
    if payload.get("previous_response_id") or payload.get("conversation"):
        raise PolicyError("Use stateless full history; provider-side references and opaque reasoning are blocked")
    if payload.get("include") not in (None, [], ["reasoning.encrypted_content"]):
        raise PolicyError("Unsupported response include fields")
    if not isinstance(payload.get("thinking", {}), dict):
        raise PolicyError("thinking must be an object")
    if payload.get("thinking", {}).get("type", "disabled") != "disabled":
        raise PolicyError("Extended thinking is not supported; disable it in the client")
    if path == "/v1/responses":
        items = payload.get("input")
        if isinstance(items, str):
            pass
        elif isinstance(items, list) and items:
            for item in items:
                if not isinstance(item, dict):
                    raise PolicyError("Unsupported input item")
                kind = item.get("type", "message")
                if kind == "message":
                    if item.keys() - {"type", "role", "content", "id", "status"}:
                        raise PolicyError("Unknown message input fields are blocked")
                    _validate_content(item.get("content"))
                elif kind in {"function_call", "function_call_output"}:
                    if item.keys() - {"type", "id", "call_id", "name", "arguments", "output", "status"}:
                        raise PolicyError("Unknown tool input fields are blocked")
                    if kind == "function_call_output":
                        _validate_content(item.get("output"))
                else:
                    raise PolicyError("Only text messages and local function tools are supported")
        else:
            raise PolicyError("A text input or non-empty input array is required")
    else:
        _validate_messages(payload.get("messages"))
    if "system" in payload:
        _validate_content(payload["system"])
    tools = payload.get("tools", [])
    if not isinstance(tools, list) or any(not isinstance(tool, dict) or tool.get("type", "function") not in {"function", "custom"} for tool in tools):
        raise PolicyError("Only client-executed function tools are supported")

    def walk(value: Any, field: str = "", data: bool = False) -> Any:
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                if session.mask(key) != key:
                    raise PolicyError("Sensitive JSON object keys cannot be forwarded safely")
                if SENSITIVE_KEYS.fullmatch(key) and child:
                    if not isinstance(child, str):
                        raise PolicyError("Credential fields must contain text")
                    result[key] = session.token(child)
                else:
                    result[key] = walk(child, key, data or key == "input" and value.get("type") == "tool_use")
            return result
        if isinstance(value, list):
            return [walk(child, field, data) for child in value]
        if isinstance(value, str):
            if field == "arguments" and not data:
                return json_bytes(walk(json_loads(value), data=True)).decode("utf-8")
            if field in {"output", "content", "text"} and value.lstrip().startswith(("{", "[")):
                try:
                    decoded = json_loads(value)
                except PolicyError:
                    pass
                else:
                    return json_bytes(walk(decoded, data=True)).decode("utf-8")
            masked = session.mask(value)
            if not data and field in {"model", "role", "type", "name", "id", "call_id", "tool_call_id", "tool_use_id"} and masked != value:
                raise PolicyError("Sensitive protocol identifiers cannot be forwarded safely")
            return masked
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if session.mask(str(value)) != str(value):
                raise PolicyError("Sensitive numeric JSON values must be supplied as text")
        return value

    result = walk(payload)
    # Clients can request encrypted reasoning by default; never ask upstream to create opaque state.
    result.pop("include", None)
    if path != "/v1/messages":
        result["store"] = False
    return result


class StreamRestorer:
    """Retain only a potential placeholder suffix between text deltas."""

    def __init__(self, mapping: dict[str, str], json_fragment: bool = False):
        self.mapping = {
            token: json.dumps(value, ensure_ascii=False)[1:-1] if json_fragment else value
            for token, value in mapping.items()
        }
        self.pattern = re.compile("|".join(re.escape(token) for token in mapping)) if mapping else None
        self.prefixes = {token[:i] for token in mapping for i in range(1, len(token))}
        self.max_length = max(map(len, mapping), default=0)
        self.pending = ""

    def feed(self, text: str, final: bool = False) -> str:
        text = self.pending + text
        keep = 0
        if not final:
            for length in range(min(len(text), self.max_length - 1), 0, -1):
                if text[-length:] in self.prefixes:
                    keep = length
                    break
        self.pending = text[-keep:] if keep else ""
        ready = text[:-keep] if keep else text
        return self.pattern.sub(lambda match: self.mapping[match.group()], ready) if self.pattern else ready


def restore_response(value: Any, mapping: dict[str, str], field: str = "") -> Any:
    if isinstance(value, dict):
        return {key: restore_response(child, mapping, key) for key, child in value.items()}
    if isinstance(value, list):
        return [restore_response(child, mapping, field) for child in value]
    if isinstance(value, str):
        return StreamRestorer(mapping, json_fragment=field == "arguments").feed(value, final=True)
    return value


class SSEProcessor:
    """Restore independent API text/tool streams while preserving SSE event order."""

    def __init__(self, path: str, mapping: dict[str, str]):
        self.path = path
        self.mapping = mapping
        self.streams: dict[tuple, StreamRestorer] = {}
        self.targets: dict[tuple, dict] = {}
        self.sequence = 0

    def encode(self, payload: dict) -> bytes:
        if "sequence_number" in payload:
            payload["sequence_number"] = self.sequence
            self.sequence += 1
        header = ("event: " + payload["type"] + "\n").encode() if "type" in payload else b""
        return header + b"data: " + json_bytes(payload) + b"\n\n"

    def flush(self, predicate: Any = None) -> bytes:
        output = []
        for key, stream in self.streams.items():
            if not stream.pending or predicate is not None and not predicate(key):
                continue
            tail = stream.feed("", final=True)
            if self.path == "/v1/chat/completions":
                if key[1] == "content":
                    delta = {"content": tail}
                elif key[1] == "tool":
                    delta = {"tool_calls": [{"index": key[2], "function": {"arguments": tail}}]}
                else:
                    delta = {"function_call": {"arguments": tail}}
                payload = {**self.targets[key], "choices": [{"index": key[0], "delta": delta, "finish_reason": None}]}
            elif self.path == "/v1/messages":
                delta = {"type": "input_json_delta", "partial_json": tail} if key[1] == "json" else {"type": "text_delta", "text": tail}
                payload = {"type": "content_block_delta", "index": key[0], "delta": delta}
            else:
                payload = {**self.targets[key], "delta": tail}
            output.append(self.encode(payload))
        return b"".join(output)

    def process(self, event: bytes) -> bytes:
        lines = event.decode("utf-8").splitlines()
        data = "\n".join(line[5:].lstrip(" ") for line in lines if line.startswith("data:"))
        if not data or data == "[DONE]":
            return (self.flush() if data == "[DONE]" else b"") + event
        payload = json_loads(data)
        if not isinstance(payload, dict):
            raise PolicyError("Unsupported SSE data")
        output = []

        def transform(container: dict, field: str, key: tuple, json_fragment: bool = False, final: bool = False) -> None:
            if field not in container:
                return
            if not isinstance(container[field], str):
                raise PolicyError("Invalid SSE text delta")
            if key not in self.streams:
                self.streams[key] = StreamRestorer(self.mapping, json_fragment)
            stream = self.streams[key]
            self.targets[key] = {k: v for k, v in payload.items() if k not in {"choices", "delta"}}
            container[field] = stream.feed(container[field], final)

        if self.path == "/v1/chat/completions":
            for choice in payload.get("choices", []):
                index = choice.get("index", 0)
                delta = choice.get("delta", {})
                final = choice.get("finish_reason") is not None
                transform(delta, "content", (index, "content"), final=final)
                for tool in delta.get("tool_calls", []):
                    transform(tool.get("function", {}), "arguments", (index, "tool", tool.get("index", 0)), True, final)
                transform(delta.get("function_call", {}), "arguments", (index, "legacy"), True, final)
                if final:
                    output.append(self.flush(lambda key: key[0] == index))
        elif self.path == "/v1/messages":
            kind = payload.get("type")
            if kind == "content_block_start":
                block = payload.get("content_block", {})
                if block.get("type") == "text":
                    transform(block, "text", (payload.get("index", 0), "text"))
                else:
                    payload["content_block"] = restore_response(block, self.mapping)
            elif kind == "content_block_delta":
                delta = payload.get("delta", {})
                index = payload.get("index", 0)
                transform(delta, "text", (index, "text"))
                transform(delta, "partial_json", (index, "json"), True)
            elif kind in {"content_block_stop", "message_stop"}:
                index = payload.get("index", 0)
                output.append(self.flush(lambda key: kind == "message_stop" or key[0] == index))
        else:
            kind = payload.get("type", "")
            if kind in {"response.output_text.delta", "response.refusal.delta", "response.function_call_arguments.delta"}:
                key = (payload.get("output_index", 0), payload.get("content_index", 0), kind)
                transform(payload, "delta", key, "arguments" in kind)
            else:
                payload = restore_response(payload, self.mapping)
                if kind in {"response.completed", "response.failed", "response.incomplete"}:
                    output.append(self.flush())
                elif kind.endswith(".done"):
                    output.append(self.flush(lambda key: key[0] == payload.get("output_index", 0)))
        output.append(self.encode(payload))
        return b"".join(output)

    def finish(self) -> None:
        if any(stream.pending for stream in self.streams.values()):
            raise PolicyError("Truncated SSE response")
