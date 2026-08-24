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
uv run python -m py_compile anonymize.py extractors.py
git diff --check
```

Use synthetic documents only. Do not add real input files or mapping files.
