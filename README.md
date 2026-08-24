# Veil

Lightweight, local, interactive document anonymizer for Windows. Veil replaces names, surnames, organizations, locations, addresses, contacts, and other PII before a document is sent to an LLM or another external service.

There is no GUI, cloud service, Node.js, or local LLM. The default workflow is a folder and one batch file.

## Fastest use: portable release

1. Download `Veil-windows-x64.zip` from the [latest GitHub Release](https://github.com/KaigorodovTuskul/veil/releases/latest).
2. Extract it to a local folder.
3. Put source files into `input`.
4. Run `run_cmd.bat`.
5. Review files in `output` before sharing them.

The target Windows machine does not need Python or modified system environment variables.

The default language is Russian. Use one portable build with a language flag:

```powershell
run_cmd.bat --lang en
run_cmd.bat --lang zh
```

You can also set `VEIL_LANG=ru`, `VEIL_LANG=en`, or `VEIL_LANG=zh`. An explicit `--lang` value takes priority.

For unattended replacement, use auto mode:

```powershell
run_cmd.bat --auto --lang en
```

Auto mode replaces every detected value and does not ask per candidate. Review the result manually before external use.

## Input and output

Supported input formats:

- TXT, JSON, CSV
- DOCX
- legacy DOC
- RTF
- text-based PDF

PPTX and OCR are not included yet. Image-only PDF pages are reported as unsafe/incomplete and are not silently treated as clean text.

Output filenames are deliberately neutral because sensitive information may be present in the source filename:

```text
input\Ivanov_Nikolay_contract.txt
output\document_001.anonymized.txt
output\document_001.txt.mapping.json
```

The original filename is stored only in the private mapping file. It is never copied to the output filename.

DOC, DOCX, and PDF are currently extracted to plain text. RTF keeps its RTF structure and formatting while replacing text; embedded RTF pictures and drawing objects are removed from the anonymized copy. The program prints warnings when a file contains unsupported or potentially unsafe content.

## Interactive review

For each detected value, choose:

```text
1 - replace this occurrence
2 - skip this occurrence
3 - replace all occurrences of this value
4 - stop without modifying the source
```

Repeated values receive the same placeholder, such as `{{PERSON_1}}` or `{{EMAIL_1}}`.

Rules are editable in [`patterns.json`](patterns.json). Detection is heuristic and best-effort: always inspect the anonymized document manually before sending it outside the machine.

## Restore an anonymized text file

Every processed file gets a mapping file containing the original sensitive values. Keep it private and never send it to an LLM.

```powershell
anonymizer.exe --restore output\document_001.anonymized.txt output\document_001.txt.mapping.json
```

The restored file is written next to the anonymized file with a `.restored` suffix. Restoration is intended for text-compatible output; it does not recreate original DOC/DOCX/PDF formatting.

## Build a portable ZIP

Requirements on the build machine: Windows, Python 3.12+, and either `uv` or standard `venv`/`pip`.

### Recommended: uv

```powershell
uv sync --locked
uv run python anonymize.py --self-test
.\build_portable.ps1
Compress-Archive -Path dist\anonymizer\* -DestinationPath dist\Veil-windows-x64.zip -Force
```

The resulting archive is `dist\Veil-windows-x64.zip`. It contains a self-contained one-folder application with `anonymizer.exe`, `patterns.json`, and `run_cmd.bat`.

### Fallback: standard Python

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe anonymize.py --self-test
powershell -NoProfile -ExecutionPolicy Bypass -File .\build_portable.ps1
Compress-Archive -Path dist\anonymizer\* -DestinationPath dist\Veil-windows-x64.zip -Force
```

## Development checks

```powershell
uv sync --locked
uv run python anonymize.py --self-test
uv run python -m py_compile anonymize.py extractors.py i18n.py
git diff --check
```

The same checks run in GitHub Actions on Windows for pushes and pull requests.

## Repository layout

```text
anonymize.py          command-line workflow, auto mode, and restore mode
extractors.py         TXT/JSON/CSV/DOC/DOCX/RTF/PDF extraction
i18n.py               Russian, English, and Simplified Chinese UI
patterns.json         configurable detection rules
run_cmd.bat           folder-mode launcher
build_portable.ps1    PyInstaller one-folder build
input/                local source files; ignored by Git
output/               local results and mappings; ignored by Git
```

## Security notes

- Mapping files contain the original values and are equivalent to sensitive data.
- Do not commit real documents, output files, mapping files, or personal data.
- A successful run is not proof that every PII value was found.
- Review every anonymized file and the console warnings before external use.

See [`SECURITY.md`](SECURITY.md), [`CONTRIBUTING.md`](CONTRIBUTING.md), and [`CHANGELOG.md`](CHANGELOG.md).

## License

No license has been selected yet. Add the license that matches the intended use before treating the repository as a distributable open-source project.
