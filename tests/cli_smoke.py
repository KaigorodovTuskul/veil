"""Optional offline two-turn CLI checks: python tests/cli_smoke.py codex|claude|opencode.

Uses isolated configuration, synthetic credentials and a loopback mock provider.
No real model is called; the mock asks the CLI to read one temporary text file.
"""

import argparse
import base64
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anonymize import load_rules
from veil_protocol import json_bytes
from veil_proxy import ProxyServer


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error":"Mock supports only inference"}')

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        if not self.path.endswith(("/responses", "/messages", "/chat/completions")):
            self.do_GET()
            return
        payload = json.loads(raw)
        self.server.calls += 1
        self.server.leaked |= any(value in raw for value in (b"test@example.com", b"synthetic-private-password"))
        tokens = re.findall(r"\{\{VEIL_[A-Za-z0-9_]*EMAIL_[0-9]+\}\}", raw.decode())
        text = "hello " + (tokens[-1] if tokens else "no email token")
        tools = payload.get("tools", [])
        for item in payload.get("input", []) if isinstance(payload.get("input"), list) else []:
            if isinstance(item, dict) and item.get("type") == "additional_tools":
                tools = tools + item.get("tools", [])
        if getattr(self.server, "subscription", False):
            self.server.auth_valid &= self.headers.get("Authorization") == "Bearer synthetic-subscription-session" and self.headers.get("ChatGPT-Account-ID") == "account-synthetic" and self.headers.get("X-Veil-Token") is None
        selected = None
        for tool in tools:
            function = tool.get("function", tool)
            if function.get("name") in {"Read", "read"}:
                selected = (function["name"], {"file_path" if function["name"] == "Read" else "path": self.server.sample}, None)
            nested = tool.get("tools", []) if tool.get("type") == "namespace" else [function]
            for child in nested:
                name = child.get("name")
                command = "type synthetic.txt" if os.name == "nt" else "cat synthetic.txt"
                if name in {"exec_command", "shell_command"}:
                    selected = (name, {"cmd" if name == "exec_command" else "command": command}, tool.get("name") if tool.get("type") == "namespace" else None)
        if self.path.endswith("/responses"):
            has_result = any(item.get("type") in {"function_call_output", "custom_tool_call_output"} for item in payload.get("input", []) if isinstance(item, dict))
        else:
            has_result = any(message.get("role") == "tool" or any(block.get("type") == "tool_result" for block in (message.get("content") or []) if isinstance(block, dict)) for message in payload.get("messages", []))
        use_tool = selected is not None and not has_result
        self.server.tool_turns += int(use_tool)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream" if payload.get("stream") else "application/json")
        self.end_headers()
        if self.path.endswith("/messages"):
            content = {"type": "tool_use", "id": "call_mock", "name": selected[0], "input": selected[1]} if use_tool else {"type": "text", "text": text}
            message = {"id": "msg_mock", "type": "message", "role": "assistant", "model": payload["model"], "content": [content], "stop_reason": "tool_use" if use_tool else "end_turn", "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 10}}
            if not payload.get("stream"):
                self.wfile.write(json_bytes(message))
                return
            frames = [{"type": "message_start", "message": {**message, "content": [], "stop_reason": None}}, {"type": "content_block_start", "index": 0, "content_block": content}, {"type": "content_block_stop", "index": 0}, {"type": "message_delta", "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None}, "usage": {"output_tokens": 10}}, {"type": "message_stop"}]
            if not use_tool:
                frames[1]["content_block"] = {"type": "text", "text": ""}
                frames.insert(2, {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}})
            else:
                frames[1]["content_block"] = {**content, "input": {}}
                frames.insert(2, {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(selected[1])}})
        elif self.path.endswith("/responses"):
            if use_tool:
                item = {"type": "function_call", "id": "fc_mock", "call_id": "call_mock", "name": selected[0], "arguments": json.dumps(selected[1]), "status": "completed"}
                if selected[2]:
                    item["namespace"] = selected[2]
            else:
                item = {"id": "msg_mock", "type": "message", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": text, "annotations": []}]}
            response = {"id": "resp_mock", "object": "response", "created_at": 0, "status": "completed", "model": payload["model"], "output": [item], "usage": {"input_tokens": 10, "output_tokens": 10, "total_tokens": 20}}
            frames = [{"type": "response.created", "response": {**response, "status": "in_progress", "output": []}}, {"type": "response.output_item.added", "output_index": 0, "item": {**item, "status": "in_progress"}}, {"type": "response.output_item.done", "output_index": 0, "item": item}, {"type": "response.completed", "response": response}]
            if self.server.subscription and use_tool:
                reasoning = {"type": "reasoning", "id": "rs_mock", "summary": [], "content": None, "encrypted_content": "opaque-reasoning-from-mock"}
                response["output"].insert(0, reasoning)
                frames[1]["output_index"] = frames[2]["output_index"] = 1
                frames.insert(1, {"type": "response.output_item.done", "output_index": 0, "item": reasoning})
            if getattr(self.server, "subscription", False):
                reasoning = {"type": "reasoning", "id": "rs_mock", "summary": [], "encrypted_content": "opaque-synthetic-reasoning"}
                frames.insert(1, {"type": "response.output_item.done", "output_index": 1, "item": reasoning})
                response["output"].insert(0, reasoning)
        else:
            delta = {"role": "assistant", "tool_calls": [{"index": 0, "id": "call_mock", "type": "function", "function": {"name": selected[0], "arguments": json.dumps(selected[1])}}]} if use_tool else {"role": "assistant", "content": text}
            base = {"id": "chat_mock", "object": "chat.completion.chunk", "created": 0, "model": payload["model"]}
            frames = [{**base, "choices": [{"index": 0, "delta": delta, "finish_reason": None}]}, {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls" if use_tool else "stop"}], "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20}}]
        for sequence, frame in enumerate(frames):
            if self.path.endswith("/responses"):
                frame["sequence_number"] = sequence
            event = ("event: " + frame["type"] + "\n").encode() if "type" in frame else b""
            self.wfile.write(event + b"data: " + json_bytes(frame) + b"\n\n")
            self.wfile.flush()
        if self.path.endswith("/completions"):
            self.wfile.write(b"data: [DONE]\n\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", choices=("codex", "claude", "opencode"))
    parser.add_argument("--codex-chatgpt", action="store_true", help="Test subscription auth using synthetic ChatGPT credentials and a loopback mock")
    args = parser.parse_args()
    if args.codex_chatgpt and args.client != "codex":
        parser.error("--codex-chatgpt requires the codex client")
    executable = shutil.which(args.client)
    if not executable:
        parser.error("Install the selected CLI first")
    # npm's Windows launcher spawns another process; prefer the installed native binary.
    if os.name == "nt" and args.client == "opencode":
        native = Path(executable).parent / "node_modules" / "@opencode" / "cli" / "bin" / "opencode.exe"
        if native.exists():
            executable = str(native)
    if os.name == "nt" and args.client == "codex":
        binaries = list(Path(executable).parent.glob("node_modules/@openai/codex/node_modules/@openai/codex-*/vendor/*/bin/codex.exe"))
        if binaries:
            executable = str(binaries[0])
    with tempfile.TemporaryDirectory(prefix="veil-cli-") as directory:
        root = Path(directory)
        sample = root / "synthetic.txt"
        sample.write_text("test@example.com\npassword=synthetic-private-password", encoding="utf-8")
        original = sample.read_bytes()
        provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        provider.daemon_threads = True
        provider.sample, provider.calls, provider.tool_turns, provider.leaked = str(sample), 0, 0, False
        provider.subscription, provider.auth_valid = args.codex_chatgpt, True
        proxy = ProxyServer(("127.0.0.1", 0), f"http://127.0.0.1:{provider.server_port}", "synthetic-provider", "synthetic-local", load_rules(), {"entries": (), "ignored": set()}, timeout=10, codex_chatgpt=args.codex_chatgpt)
        for server in (provider, proxy):
            threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        env = {key: value for key, value in os.environ.items() if key.upper() in {"SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "PATH", "TEMP", "TMP", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "PROGRAMFILES", "PROGRAMFILES(X86)"}}
        env.update({"HOME": directory, "USERPROFILE": directory, "APPDATA": directory, "LOCALAPPDATA": directory, "XDG_CONFIG_HOME": directory, "XDG_DATA_HOME": directory, "XDG_CACHE_HOME": directory, "VEIL_PROXY_TOKEN": "synthetic-local", "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9", "NO_PROXY": "localhost,127.0.0.1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1"})
        base = f"http://127.0.0.1:{proxy.server_port}"
        prompt = "Read synthetic.txt with the local read tool, then report its contact."
        if args.client == "codex":
            config = root / "codex"
            config.mkdir()
            env["CODEX_HOME"] = str(config)
            authentication = 'requires_openai_auth=true\nenv_http_headers={"X-Veil-Token"="VEIL_PROXY_TOKEN"}' if args.codex_chatgpt else 'env_key="VEIL_PROXY_TOKEN"'
            (config / "config.toml").write_text(f'model="mock"\nmodel_provider="veil"\nchatgpt_base_url="http://127.0.0.1:{provider.server_port}"\nweb_search="disabled"\napproval_policy="never"\n[model_providers.veil]\nname="Veil"\nbase_url="{base}/v1"\n{authentication}\nwire_api="responses"\nsupports_websockets=false\nrequest_max_retries=0\nstream_max_retries=0\n', encoding="utf-8")
            if args.codex_chatgpt:
                template = Path(__file__).resolve().parents[1] / "config" / "codex-chatgpt.config.toml.example"
                profile = template.read_text(encoding="utf-8").replace("http://127.0.0.1:8765", base)
                (config / "veil-chatgpt.config.toml").write_text(profile, encoding="utf-8")
                (config / "config.toml").write_text(f'model="mock"\nchatgpt_base_url="http://127.0.0.1:{provider.server_port}"\napproval_policy="never"\n', encoding="utf-8")
                claims = {"exp": 4102444800, "email": "synthetic@example.invalid", "https://api.openai.com/auth": {"chatgpt_account_id": "account-synthetic", "chatgpt_user_id": "user-synthetic", "chatgpt_plan_type": "plus"}}
                encoded = base64.urlsafe_b64encode(json_bytes(claims)).decode().rstrip("=")
                id_token = "eyJhbGciOiJub25lIn0." + encoded + ".synthetic"
                auth = {"auth_mode": "chatgpt", "tokens": {"id_token": id_token, "access_token": "synthetic-subscription-session", "refresh_token": "synthetic-refresh", "account_id": "account-synthetic"}, "last_refresh": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")}
                (config / "auth.json").write_bytes(json_bytes(auth))
            # Only our fixed mock command reads our temporary file; no real model chooses commands.
            command = [executable, "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-rules", "--sandbox", "danger-full-access", "--json", prompt]
            if args.codex_chatgpt:
                command[2:2] = ["--profile", "veil-chatgpt", "-c", "model_providers.veil_chatgpt.request_max_retries=0", "-c", "model_providers.veil_chatgpt.stream_max_retries=0"]
        elif args.client == "claude":
            env.update({"CLAUDE_CONFIG_DIR": directory, "ANTHROPIC_API_KEY": "synthetic-local", "ANTHROPIC_BASE_URL": base, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "MAX_THINKING_TOKENS": "0", "CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING": "1"})
            command = [executable, "--bare", "-p", prompt, "--model", "claude-sonnet-4-6", "--system-prompt", "Synthetic offline test.", "--tools", "Read", "--allowedTools", "Read", "--no-session-persistence", "--output-format", "json", "--max-turns", "3"]
        else:
            configuration = {"model": "veil/mock", "providers": {"veil": {"name": "Veil", "env": ["VEIL_PROXY_TOKEN"], "package": "@opencode/ai/providers/openai-compatible", "settings": {"baseURL": base + "/v1", "apiKey": "{env:VEIL_PROXY_TOKEN}", "encoding": "none"}, "models": {"mock": {"name": "Offline mock", "limit": {"context": 32000, "output": 1024}}}}}, "snapshots": False}
            (root / "opencode.json").write_bytes(json_bytes(configuration))
            command = [executable, "--standalone", "run", "--format", "json", prompt]
        try:
            result = subprocess.run(command, cwd=root, env=env, input="", capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
            passed = result.returncode == 0 and "hello test@example.com" in result.stdout and provider.tool_turns >= 1 and not provider.leaked and provider.auth_valid and sample.read_bytes() == original
            print(json.dumps({"client": args.client, "subscription_auth": args.codex_chatgpt, "passed": passed, "returncode": result.returncode, "provider_calls": provider.calls, "tool_turns": provider.tool_turns, "original_reached_provider": provider.leaked, "auth_forwarding_valid": provider.auth_valid, "stdout_tail": result.stdout[-2000:] if not passed else None, "stderr_tail": result.stderr[-1000:] if not passed else None}, ensure_ascii=False, indent=2))
            return 0 if passed else 1
        finally:
            for server in (proxy, provider):
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
