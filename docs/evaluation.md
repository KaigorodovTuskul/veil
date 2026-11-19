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

## Round 3 — `2e29c76`

| Reviewer focus | Effectiveness | Simplicity / ease | Speed | Mean |
| --- | ---: | ---: | ---: | ---: |
| Privacy and protocol correctness | 8.8 | 8.5 | 8.7 | 8.67 |
| Terminal user experience | 8.8 | 8.8 | 9.0 | 8.87 |
| Performance and maintainability | 8.8 | 8.7 | 8.8 | 8.77 |
| **Round mean** | | | | **8.77** |

The unrounded mean is 78.9 / 9 = 8.7666…, which exceeds the requested 8.5
threshold. Reviewers found no remaining blocking defect in the documented local
text scenario. All 28 tests passed. The privacy and user-experience reviewers
independently reran all three real CLI two-turn mock checks successfully.

Confirmed fixes: sensitive permitted headers produce 422 with zero provider
requests, fragmented custom-tool input restores exact text, and the expanded
long-word/punctuation regressions finish within their subprocess deadline.

Current local measurements: 100 KiB repeated text around 140 ms; 100,000-character
ASCII/Cyrillic/adversarial inputs around 100–150 ms; 5000 unique email values
around 160 ms for masking and 283 ms for the full request; restoration of 201
fields / 1000 mappings around 25 ms; SSE around 120,000 frames per second.

The final Windows portable executable was rebuilt and independently exercised
against a loopback mock: built-in self-test, proxy help, authenticated health,
JSON and SSE forwarding/restoration passed, and the original email did not reach
the provider. No real cloud credentials or documents were used.

Recommended subsequent work is corpus-based detection/utility evaluation for the
user's document types, with organization-specific dictionaries. It is separate
from this completed implementation/review cycle; the current scores do not claim
perfect redaction or certification.

## Codex subscription follow-up

The first subscription review covered `0d3daa6`, with 38 tests and a real Codex
CLI 0.165.0 two-turn offline smoke. Review scores were 8.40 for privacy, 8.90 for
user experience and 8.80 for performance (overall 8.70). A reproducible utility
defect remained: replayed encrypted reasoning could return an old placeholder
whose restoration table had already been discarded.

The correction associates an immutable restoration snapshot with each observed
account-bound reasoning digest. Replay imports that snapshot for restoration and
known-secret masking. The cache keeps its 1024-entry / 30-minute idle bounds and
adds a conservative 16 MiB allocation budget. Oversized history is not admitted;
cache misses remain fail-closed. Original values now remain in local memory for
the cache lifetime, as documented in SECURITY.md and proxy.md.

| Final reviewer focus | Effectiveness | Simplicity / ease | Speed | Mean |
| --- | ---: | ---: | ---: | ---: |
| Privacy and protocol correctness | 8.9 | 8.6 | 8.7 | 8.73 |
| Terminal user experience | 8.9 | 9.0 | 9.0 | 8.97 |
| Performance and maintainability | 8.9 | 8.9 | 8.8 | 8.87 |
| **Round mean** | | | | **8.86** |

The unrounded mean is 79.7 / 9 = 8.8555..., above 8.5. All three reviewers
independently rechecked the corrected working tree and found no remaining
reproducible blocker in this scenario. Snapshot import of 1000 pairs took about
0.06 ms. A separate 200-snapshot budget check retained 13 snapshots of 1000 pairs,
using an estimated 16,320,044 bytes, below the 16 MiB budget. This budget is for
the cache, not the entire Python process.

All 40 tests pass. New two-turn HTTP regressions deliberately return the first
turn's tokens in the second JSON/SSE response, including tool arguments. They
also check inherited short-secret masking, snapshot isolation, account isolation
and byte-budget eviction. The actual Codex subscription-profile offline smoke
passes: two provider requests, one local file read, no original values upstream,
correct bearer/account forwarding and unchanged source file. Previous API-mode
Codex, Claude Code and OpenCode smoke checks also passed during the review.

The rebuilt Windows executable passes subscription-mode authenticated health,
JSON and SSE checks against a loopback mock, with no original email forwarded.

A separate live check used the existing ChatGPT sign-in and gpt-6.1-sol with a
synthetic email only. Veil masked it before the network call, the real service
returned HTTP 200, and Codex displayed the restored email. A live attempt to read
the synthetic file was blocked by the local Codex access policy; that policy was
not weakened. Thus real-service echo is verified, while the successful file/tool
workflow is established with the actual CLI and a mock provider. Automatic token
refresh, subscription quotas and arbitrary document workflows were not tested.

## Scope of evidence

Tests inspect mock-provider request bodies and exercise response reconstruction.
They do not establish completeness of PII/secret detection, inspect real private
documents or enforce OS-level isolation on the user's agent. Only the separate
subscription check above contacted a real cloud model, using synthetic content.
See [proxy.md](proxy.md) and [SECURITY.md](../SECURITY.md).
