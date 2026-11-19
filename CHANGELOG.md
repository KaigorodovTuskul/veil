# Changelog

## Unreleased

- Added `--codex-chatgpt` for Codex subscription sign-in without a provider API key, with a separate local credential and a pinned upstream.
- Added account-bound, bounded reasoning replay provenance, Responses Lite plaintext inputs, and validated subscription SSE responses without Content-Type.
- Preserve old reasoning placeholders using account-bound restoration snapshots with a 16 MiB cache budget and 30-minute idle expiry.
- Added an isolated synthetic subscription CLI smoke and a selectable Codex profile template.
- Added a loopback-only privacy proxy for text requests to Chat Completions, Responses and Anthropic Messages APIs, including JSON/SSE tool-call restoration.
- Proxy checks fail closed; unsupported paths, attachments, provider-side state and opaque content are blocked.
- API provider credentials stay in the proxy; subscription credentials are forwarded by Codex. Local client authentication is required. Mappings stay in local memory and payloads are not logged.
- Added provider credentials, private keys, JWTs, payment cards with Luhn checks and contextual bank accounts to detection rules.
- Fixed Unicode restoration, overlapping match coverage and literal placeholder collisions; compiled rules are reused.
- Added synthetic integration tests and cross-platform CI.
- Added optional local user dictionaries for keywords and ignored phrases.
- User dictionary matching is case-insensitive and supports aliases without new dependencies.

## 0.2.0

- Made regex matching case-insensitive for uppercase documents.
- Added normalization for invisible spaces and dash variants.
- Added organization suffix detection for joined and spaced names such as `Пупкинбанк` and `Пуп кинбанк`.
- Removed broad city-by-preposition matching and added context stop words to reduce false positives.
- Fixed RTF replacement offsets and batch processing so one broken file does not stop the remaining files.
- Documented launcher arguments in `run_cmd.bat`.
- Added `--auto` mode for unattended replacement.
- Added Russian, English, and Simplified Chinese UI via `--lang` or `VEIL_LANG`.
- Output filenames now preserve safe source parts and remove detected sensitive fragments; removed values remain only in private mappings.
- Expanded detection for names, initials, inflected names, cities, regions, countries, organizations, addresses, and email punctuation.
- Preserved RTF structure while replacing text.
- Fixed RTF Unicode fallback characters that could remain after a replacement.
- Added detection for initials-before-surname patterns and foreign company names after explicit company context.
- Added country detection inside ordinary sentences, including inflected forms such as `России`.
- Included RTF headers and footers in extraction and replacement; added regression coverage for Yakutsk and the Sakha Republic.
- Removed embedded RTF pictures and drawing objects from anonymized output.
- Added portable Windows build documentation and CI configuration.
