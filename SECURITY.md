# Security policy

Veil is a local preprocessing tool and text-only LLM privacy proxy. It is not a guarantee that every sensitive value will be found.

## Proxy trust boundary

- Run the harness and Veil locally. The proxy holds raw data and provider credentials in memory.
- The proxy requires a local token, binds only to loopback and blocks unsupported content and inspection failures. There is no passthrough mode.
- Protect `config/proxy_token`, your provider-key environment, crash dumps and agent transcripts. The proxy does not write request mappings or payload logs.
- Restrict harness network egress and external tools separately. A changed API base URL does not stop direct HTTP, uploads, telemetry or remote MCP calls.
- Names removed from a document do not hide confidential financial results, inventions or identity inferred from context.
- Review custom rules and ignore lists. Restart the proxy after changes.
- The server is for a trusted local user; do not publish it through a tunnel or shared ingress. Local processes with the same account may be able to read its token and memory.
- In `--codex-chatgpt` mode, Codex retains sign-in/refresh ownership. Its bearer and account ID go only to the fixed ChatGPT service (or an explicit loopback test server); the separate `X-Veil-Token` never goes upstream.
- Encrypted reasoning is accepted only after observation through this proxy for the same account. The cache stores hashes and sensitive original-value restoration tables in local memory, expires for replay after 30 idle minutes, holds at most 1024 entries and uses a conservative 16 MiB allocation budget. Expired entries are removed on the next cache access or process exit, not by a background erasure timer. Evicted or oversized history is blocked. Restarting Veil requires a fresh session; unknown opaque input is blocked.

See [docs/proxy.md](docs/proxy.md) for supported protocols, limits and setup.

## Safe usage

- Review every anonymized file before sending it to an external service.
- Keep `*.mapping.json` files private. They contain the original values.
- Do not commit real documents, mappings, or personal data to this repository.
- Use synthetic fixtures for tests and issue reports.

## Reporting a vulnerability

Do not publish real personal data in a public issue. Contact the repository owner privately with a minimal reproduction and sanitized sample.
