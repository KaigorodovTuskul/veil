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

## Scope of evidence

Tests inspect mock-provider request bodies and exercise response reconstruction.
They do not establish completeness of PII/secret detection, inspect real private
documents, invoke a paid cloud model, or enforce OS-level isolation on the user's
agent. See [proxy.md](proxy.md) and [SECURITY.md](../SECURITY.md).
