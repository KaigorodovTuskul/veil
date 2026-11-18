# Independent evaluation rounds

The user requested independent subagent reviews of effectiveness, simplicity and
ease of use, and speed. Every reviewer scores **all three** criteria out of ten.
The round mean is the arithmetic mean of all nine scores, with equal weights.
The completion threshold is strictly greater than 8.5. Scores are reviewer
judgments supported by checks, not security certification or detection accuracy.

## Round 1 — `c3a0468` (pushed before review)

| Reviewer focus | Effectiveness | Simplicity / ease | Speed | Mean |
| --- | ---: | ---: | ---: | ---: |
| Privacy and protocol correctness | 6.5 | 7.5 | 8.0 | 7.33 |
| Terminal user experience | 7.5 | 7.0 | 8.5 | 7.67 |
| Performance and maintainability | 7.5 | 8.0 | 5.5 | 7.00 |
| **Round mean** | | | | **7.33** |

All reviewers ran the 21 synthetic tests. The user-experience reviewer also
verified real Claude Code 2.1.109 against a loopback mock provider; a two-turn
Read tool exchange restored the email without sending the original upstream.
Codex 0.165.0 exposed an unsupported namespace tool. Separate OpenCode v2.2.5
checks verified its current provider configuration and two-turn file reading.

Required changes identified and implemented for reassessment:

1. Collect detected/explicit credentials before applying replacements across the
   entire request, so an original does not escape through an earlier field.
2. Distinguish JSON Schema properties from actual credential fields; cover
   `token`, `refresh_token` and `aws_secret_access_key` as well as passwords.
3. Add Responses local namespace/custom tool history support and persistent
   optional offline two-turn checks for the installed CLI binaries.
4. Track SSE completion and reject post-terminal data/truncated responses.
5. Fix unbounded retry positions in the foreign-organization regex, assemble
   replacements with one join, and share prepared response restoration tables.
6. Expose proxy mode in normal CLI help and document a verified OpenCode config.

Observed baseline measurements on this Windows machine: masking 100 KiB of
repeated synthetic content around 167 ms; 201 JSON string fields with 1000 mapping
values around 699 ms; a 20,000-character unbroken lowercase word exceeded a
5-second subprocess timeout. Run `tests/benchmark.py` for current values; absolute
times are hardware-dependent and the benchmark uses synthetic data.

## Round 2 — `bdbc516`

| Reviewer focus | Effectiveness | Simplicity / ease | Speed | Mean |
| --- | ---: | ---: | ---: | ---: |
| Privacy and protocol correctness | 8.0 | 8.5 | 8.5 | 8.33 |
| Terminal user experience | 8.0 | 8.5 | 8.8 | 8.43 |
| Performance and maintainability | 8.0 | 8.7 | 6.5 | 7.73 |
| **Round mean** | | | | **8.11** |

All 26 tests passed. Reviewers independently confirmed the permanent Codex,
Claude Code and OpenCode two-turn mock tests. The prior issues were fixed, but
reassessment found:

1. Header inspection reused a sealed session and could miss a new sensitive
   value appearing only in a permitted provider header.
2. Fragmented Responses custom-tool input events were not restored.
3. Other old regex rules still retried inside long uppercase/mixed/Cyrillic
   words. The lowercase-only regression was insufficient.

Changes for the next assessment independently scan provider headers, add custom
tool input stream restoration, fix all identified start boundaries and ambiguous
secret separators, and expand bounded subprocess regressions and the full-request
benchmark. An incomplete private-key block is now masked through the end of text.

Observed improved values: 100 KiB repeated content around 133 ms, 5000 unique
emails around 150 ms (full proxy request around 270 ms), and restoration of 201
fields with 1000 mapping values around 25 ms.

## Scope of evidence

Tests inspect mock-provider request bodies and exercise response reconstruction.
They do not establish completeness of PII/secret detection, inspect real private
documents, invoke a paid cloud model, or enforce OS-level isolation on the user's
agent. See [proxy.md](proxy.md) and [SECURITY.md](../SECURITY.md).
