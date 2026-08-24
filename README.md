# Veil

Veil is a lightweight, local document anonymizer for preparing files before sending their text to an LLM.

It has no GUI and no local LLM. The program finds sensitive values with configurable regular-expression rules, asks for confirmation, and writes anonymized results without changing the original files.

## Quick start

1. Put source files into the `input` folder.
2. Run `run_cmd.bat`.
3. Take anonymized files from the `output` folder.

Supported input formats:

- TXT, JSON, CSV
- DOCX
- DOC (legacy Word)
- RTF
- PDF with an extractable text layer

PPTX and OCR are not supported yet. Image-only PDFs are rejected with a warning instead of producing a potentially unsafe result.

## Portable package

The repository includes a build script for Windows. The target machine does not need Python and no system environment variables are changed.

On the build machine:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
powershell -NoProfile -ExecutionPolicy Bypass -File .\build_portable.ps1
```

The portable package is created in `dist\anonymizer\` and contains:

```text
anonymizer.exe
patterns.json
run_cmd.bat
```

Copy that folder to another Windows machine, put files into its `input` folder, and run its `run_cmd.bat`.

## Development mode

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe anonymize.py --self-test
```

Running `anonymize.py` without arguments uses `input` and `output` next to the script. File paths can also be passed directly for development:

```powershell
.\.venv\Scripts\python.exe anonymize.py document.docx
```

## Review actions

For each detected value:

```text
1 - replace this value
2 - skip this value
3 - replace all occurrences of this value
4 - stop without modifying the source
```

Repeated values receive the same placeholder, for example `{{PERSON_1}}` or `{{EMAIL_1}}`.

## Output and restoration

Text formats keep their extension:

```text
input\contract.txt
output\contract.anonymized.txt
output\contract.txt.mapping.json
```

Document formats are converted to cleaned text:

```text
input\contract.docx
output\contract.docx.anonymized.txt
output\contract.docx.mapping.json
```

Restore text with the saved mapping:

```powershell
anonymizer.exe --restore output\contract.anonymized.txt output\contract.txt.mapping.json
```

The mapping contains the original sensitive values. Keep it local, do not send it to an LLM, and do not commit it to Git.

## Detection rules

Rules are stored in [`patterns.json`](patterns.json). The default set covers email addresses, phone numbers, INN, SNILS, passport numbers, API keys, context-based names, and context-based addresses.

Automatic detection is best-effort and does not guarantee that every sensitive value is found. Review the output before sending it to an external service.

## Limitations

- DOC/DOCX/RTF/PDF output is plain text; original formatting is not preserved.
- OCR is disabled. Image-only PDF pages are refused or reported as incomplete.
- PPTX is not supported yet.
- Mapping files are currently plain JSON and are not encrypted.
