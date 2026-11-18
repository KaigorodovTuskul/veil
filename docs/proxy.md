# Veil privacy proxy

Veil can sit between a **local** agent harness and an LLM API. The harness reads
original files on your machine; Veil replaces detected values before sending the
request, and restores them in the model's response and local tool calls. The
proxy does not edit your source files. An agent with write access still can.

This is reversible pseudonymization, not a guarantee of anonymity. Decide which
facts must stay private: business terms and financial results may be confidential
even after every name has been removed. Add organization-specific terms to
`config/user_keywords.csv` and test synthetic examples before real documents.

## Start the proxy

Install the existing Python dependencies (`uv sync --locked`), then use a terminal
dedicated to the proxy. You need an API credential accepted by the upstream;
an interactive agent subscription is not automatically an API credential.

PowerShell:

```powershell
# Set these in this terminal, using your secret manager or secure environment.
# VEIL_UPSTREAM_API_KEY must contain the real provider credential.
$env:VEIL_UPSTREAM_BASE_URL = "https://api.anthropic.com"
uv run python anonymize.py --proxy
```

Bash:

```bash
# VEIL_UPSTREAM_API_KEY must already be set securely in this terminal.
export VEIL_UPSTREAM_BASE_URL=https://api.anthropic.com
uv run python anonymize.py --proxy
```

The default address is `http://127.0.0.1:8765`. Change it with `--port`.
`--upstream` overrides `VEIL_UPSTREAM_BASE_URL`; both a bare provider URL and one
ending in `/v1` work. Use a separate instance/port for each provider.
HTTPS and certificate validation are required upstream. Plain HTTP is accepted
only for a loopback mock provider. No environment HTTP proxy or redirects are used.

On first start Veil creates `config/proxy_token`, excluded from Git. Set
`VEIL_PROXY_TOKEN` to use your own local client credential instead. Keep the proxy
terminal open. Do not put the real provider credential in the agent terminal:
the agent needs only the local token. Veil replaces client auth with the provider
credential; arbitrary client headers and cookies are not forwarded.

## Connect a client

In a **second** PowerShell terminal, from the Veil checkout:

```powershell
$env:VEIL_PROXY_TOKEN = (Get-Content -Raw config/proxy_token).Trim()
```

Or Bash:

```bash
export VEIL_PROXY_TOKEN="$(cat config/proxy_token)"
```

Use the configured environment value instead if you set `VEIL_PROXY_TOKEN`
explicitly in the proxy terminal. The file is not created in that case.

### Claude Code / Anthropic Messages

Point the proxy upstream at `https://api.anthropic.com`, then in the agent terminal:

```powershell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8765"
$env:ANTHROPIC_AUTH_TOKEN = $env:VEIL_PROXY_TOKEN
Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue
$env:MAX_THINKING_TOKENS = "0"
$env:CLAUDE_CODE_DISABLE_ADAPTIVE_THINKING = "1"
claude
```

Start a fresh text-only session. Extended/signed thinking, images, PDFs and
provider-executed tools are blocked. API clients that send both authorization
and `x-api-key` must be configured to use only one local credential header.
The SDK's `/v1/messages?beta=true` route is accepted as `/v1/messages`.

### Codex / Responses

Point a separate Veil instance upstream at `https://api.openai.com`, then configure
a custom provider in the client's configuration:

```toml
model_provider = "veil"
web_search = "disabled"

[model_providers.veil]
name = "Veil local privacy proxy"
base_url = "http://127.0.0.1:8765/v1"
env_key = "VEIL_PROXY_TOKEN"
wire_api = "responses"
supports_websockets = false
```

Keep your chosen model setting. Use text-only full-history sessions. Veil forces
`store=false` and removes the request for encrypted reasoning output. Requests
that replay encrypted reasoning, item references, `previous_response_id` or a
provider conversation are rejected; the proxy cannot inspect that hidden context.
Remote compaction and hosted web search are not supported. Protocol tests cover
Responses text/tool/SSE exchanges; CLI-specific capabilities depend on the client
release and must be verified before use with private files.

### OpenCode / OpenAI-compatible clients

The following `opencode.json` format was tested with OpenCode **v2.2.5**:

```json
{
  "model": "veil/YOUR_MODEL_ID",
  "providers": {
    "veil": {
      "name": "Veil",
      "env": ["VEIL_PROXY_TOKEN"],
      "package": "@opencode/ai/providers/openai-compatible",
      "settings": {
        "baseURL": "http://127.0.0.1:8765/v1",
        "apiKey": "{env:VEIL_PROXY_TOKEN}",
        "encoding": "none"
      },
      "models": {
        "YOUR_MODEL_ID": {
          "name": "Your provider model"
        }
      }
    }
  },
  "snapshots": false
}
```

Replace `YOUR_MODEL_ID` in both places with your provider's model ID. Keep request
compression disabled (`encoding: none`): Veil inspects uncompressed JSON. Start
with `opencode --standalone` so an existing background service does not reuse
different endpoint settings. Older OpenCode versions use a different schema.
Other OpenAI-compatible clients also use the `/v1` base URL and local Veil token.
Anthropic clients use the base URL without `/v1`.

### Synthetic connectivity check

PowerShell:

```powershell
$headers = @{ Authorization = "Bearer $env:VEIL_PROXY_TOKEN" }
Invoke-RestMethod http://127.0.0.1:8765/healthz -Headers $headers
```

Health is local; it does not contact the provider. For an actual provider call,
use a synthetic email and an authorized model. A valid cloud API key can incur
the provider's normal usage charges. For a completely offline check, run:

```text
uv run python -m unittest discover -s tests -v
uv run python tests/benchmark.py
```

The tests use a local mock provider and inspect what it receives, including
fragmented UTF-8/SSE and escaped tool arguments. They require no external account.

Optional checks of installed CLI binaries:

```text
uv run python tests/cli_smoke.py codex
uv run python tests/cli_smoke.py claude
uv run python tests/cli_smoke.py opencode
```

Verified locally with Codex **0.165.0**, Claude Code **2.1.109** and OpenCode
**v2.2.5**. Each check creates isolated temporary configuration, reads a synthetic
local file through a real tool call and verifies that its email/password do not
reach the mock provider. It also checks the restored final answer and unchanged
source. The Codex check runs only the mock's fixed file-read command with sandbox
disabled because a fresh temporary Windows profile has no configured sandbox;
this does not alter your normal Codex settings. These checks do not verify cloud
credentials, model quality or arbitrary CLI features.

## Supported contract and failure behavior

| Operation | Behavior |
| --- | --- |
| `POST /v1/chat/completions` | Text history, local function tools; JSON and SSE |
| `POST /v1/responses` | Stateless text input, function calls/results; JSON and SSE |
| `POST /v1/messages` | Text system/history, local tool inputs/results; JSON and SSE |
| `GET /v1/models` | Authenticated provider model discovery |
| `GET /healthz`, `/readyz` | Authenticated local process health |
| Other paths, query parameters or methods | Rejected; no blind passthrough |

Detection reuses `patterns.json` and local user dictionaries, loaded at startup.
Restart the proxy after editing them. Ignore-list entries deliberately allow
those values through; review that file as part of your privacy policy.
One original value gets one random-namespace placeholder across an entire request.
Veil first collects findings across all fields, including explicit credential
fields, then masks their occurrences throughout the request regardless of field
order. Tool JSON Schemas are distinguished from actual argument values.
Each request has an independent mapping; simultaneous users never share mappings.
Mappings exist in memory until that request completes, with no database or audit
payload storage. Process dumps and local memory access remain sensitive.

Unknown top-level/message/content fields are blocked. Binary/image/audio/file
content, provider-side history and hosted tools are not inspected and cannot be
sent through the proxy. Extract document text **locally** using Veil's existing
file mode before including it in a prompt. Numeric JSON fields detected as
sensitive are rejected rather than silently changing the tool's JSON types.

HTTP requests are bounded to 8 MiB, JSON responses to 16 MiB and individual SSE
frames to 1 MiB. At most 16 connections are processed at once. A slow client has
a 30-second socket timeout; the provider idle timeout defaults to 120 seconds and
can be changed with `--timeout`. The standard-library HTTP server is intended
for one trusted local user, not a public multi-tenant service.

Errors before forwarding return a local error without sending the request.
There is **no fail-open switch**. Invalid/unsupported provider responses return
502; a failure after SSE headers emits a generic stream error and closes the
connection without a success terminator. EOF before the protocol's completion
event is treated as a truncated response.
Provider errors preserve the status but hide their raw body to avoid reflected
secrets. Request/response bodies, credentials and original values are not logged.
The local token is required even on health endpoints; browser-origin requests
and non-loopback Host headers are refused.

## Agent isolation still matters

Changing a base URL does not enforce network isolation. Restrict the harness's
network destinations, file access and external tools with OS/container controls.
Block direct model API access and arbitrary outbound HTTP from the harness;
only the proxy process should reach the provider. Check telemetry, MCP servers,
web tools, subprocesses and local agent conversation logs separately. Veil cannot
impose these controls on a process that runs with your normal account privileges.

Masking reduces prompt-cache reuse because namespaces change per request.
Exact placeholders are restored; a model that rewrites one may leave an unresolved
token. Test utility as well as missed detections on your own document categories.

## Design reference

The mask → forward → restore design was informed by
[Cloud.ru guardrails-llm-filter](https://github.com/cloud-ru-tech/guardrails-llm-filter).
Veil reuses its own Python detector and has no Go service, database, admin UI,
ML dependency or imported Cloud.ru source. Unlike the reference's deliberate
fail-open design, Veil blocks requests it cannot inspect.

Client references: [Claude Code gateways](https://code.claude.com/docs/en/llm-gateway),
[Codex configuration](https://developers.openai.com/codex/config-reference/),
[OpenCode providers](https://opencode.ai/docs/providers/).
