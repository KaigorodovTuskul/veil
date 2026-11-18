# Contributing

## Local setup

```powershell
uv sync
uv run python anonymize.py --self-test
```

The fallback setup is documented in `README.md` for machines where `uv` is unavailable.

## Before opening a pull request

```powershell
uv run python anonymize.py --self-test
uv run python -m unittest discover -s tests -v
uv run python -m py_compile anonymize.py extractors.py i18n.py veil_proxy.py veil_protocol.py
git diff --check
```

Smoke-test the non-interactive path with a synthetic file:

```powershell
uv run python anonymize.py --auto --lang en
```

Use synthetic documents only. Do not add real input files or mapping files.

The privacy tests start loopback mock providers, inspect exactly what is forwarded,
and verify JSON/SSE tool-call restoration. They need no cloud account or API key.
Run `uv run python tests/benchmark.py` to measure local masking and SSE overhead.
