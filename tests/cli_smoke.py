"""Optional offline two-turn CLI checks: python tests/cli_smoke.py codex|claude|opencode.

Uses isolated configuration, synthetic credentials and a loopback mock provider.
No real model is called; the mock asks the CLI to read one temporary text file.
"""

import argparse
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

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        payload = json.loads(raw)
        self.server.calls += 1
        self.server.leaked |= any(value in raw for value in (b"test@example.com", b"synthetic-private-password"))
        tokens = re.findall(r"\{\{VEIL_[A-Za-z0-9_]*EMAIL_[0-9]+\}\}", raw.decode())
        text = "hello " + (tokens[-1] if tokens else "no email token")
        tools = payload.get("tools", [])
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
    args = parser.parse_args()
    executable = shutil.which(args.client)
    if not executable:
        parser.error("Install the selected CLI first")
    # npm's Windows launcher spawns another process; prefer the installed native binary.
    if os.name == "nt" and args.client == "opencode":
        native = Path(executable).parent / "node_modules" / "@opencode" / "cli" / "bin" / "opencode.exe"
        if native.exists():
            executable = str(native)
    with tempfile.TemporaryDirectory(prefix="veil-cli-") as directory:
        root = Path(directory)
        sample = root / "synthetic.txt"
        sample.write_text("test@example.com\npassword=synthetic-private-password", encoding="utf-8")
        original = sample.read_bytes()
        provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        provider.daemon_threads = True
        provider.sample, provider.calls, provider.tool_turns, provider.leaked = str(sample), 0, 0, False
        proxy = ProxyServer(("127.0.0.1", 0), f"http://127.0.0.1:{provider.server_port}", "synthetic-provider", "synthetic-local", load_rules(), {"entries": (), "ignored": set()}, timeout=10)
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
            (config / "config.toml").write_text(f'model="mock"\nmodel_provider="veil"\nweb_search="disabled"\napproval_policy="never"\n[model_providers.veil]\nname="Veil"\nbase_url="{base}/v1"\nenv_key="VEIL_PROXY_TOKEN"\nwire_api="responses"\nsupports_websockets=false\nrequest_max_retries=0\nstream_max_retries=0\n', encoding="utf-8")
            # Only our fixed mock command reads our temporary file; no real model chooses commands.
            command = [executable, "exec", "--skip-git-repo-check", "--ephemeral", "--ignore-rules", "--sandbox", "danger-full-access", "--json", prompt]
        elif args.client == "claude":
            env.update({"CLAUDE_CONFIG_DIR": directory, "ANTHROPIC_API_KEY": "synthetic-local", "ANTHROPIC_BASE_URL": base, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "MAX_THINKING_TOKENS": "0", "CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING": "1"})
            command = [executable, "--bare", "-p", prompt, "--model", "claude-sonnet-4-6", "--system-prompt", "Synthetic offline test.", "--tools", "Read", "--allowedTools", "Read", "--no-session-persistence", "--output-format", "json", "--max-turns", "3"]
        else:
            configuration = {"model": "veil/mock", "providers": {"veil": {"name": "Veil", "env": ["VEIL_PROXY_TOKEN"], "package": "@opencode/ai/providers/openai-compatible", "settings": {"baseURL": base + "/v1", "apiKey": "{env:VEIL_PROXY_TOKEN}", "encoding": "none"}, "models": {"mock": {"name": "Offline mock", "limit": {"context": 32000, "output": 1024}}}}}, "snapshots": False}
            (root / "opencode.json").write_bytes(json_bytes(configuration))
            command = [executable, "--standalone", "run", "--format", "json", prompt]
        try:
            result = subprocess.run(command, cwd=root, env=env, input="", capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=45)
            passed = result.returncode == 0 and "hello test@example.com" in result.stdout and provider.tool_turns >= 1 and not provider.leaked and sample.read_bytes() == original
            print(json.dumps({"client": args.client, "passed": passed, "returncode": result.returncode, "provider_calls": provider.calls, "tool_turns": provider.tool_turns, "original_reached_provider": provider.leaked, "stdout_tail": result.stdout[-2000:] if not passed else None, "stderr_tail": result.stderr[-1000:] if not passed else None}, ensure_ascii=False, indent=2))
            return 0 if passed else 1
        finally:
            for server in (proxy, provider):
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
