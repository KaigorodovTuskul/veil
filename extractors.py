"""Text extraction adapters used by the local anonymizer."""

from __future__ import annotations

import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from i18n import tr


class ExtractionError(Exception):
    """The file cannot safely be converted to text."""


@dataclass(frozen=True)
class Extraction:
    text: str
    warnings: tuple[str, ...] = ()
    marked: tuple[dict[str, Any], ...] = ()


def read_text(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    encodings = ("utf-8-sig", "utf-8", "cp1251", "latin-1") if data.startswith(b"\xef\xbb\xbf") else ("utf-8", "cp1251", "latin-1")
    for encoding in encodings:
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise UnicodeError(tr("encoding_error", value=path))


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _docx_part_text(data: bytes) -> str:
    root = ElementTree.fromstring(data)
    chunks: list[str] = []

    def walk(node: ElementTree.Element) -> None:
        for child in node:
            walk(child)
        name = _local_name(node.tag)
        if name == "t" and node.text:
            chunks.append(node.text)
        elif name == "tab":
            chunks.append("\t")
        elif name in {"br", "cr"}:
            chunks.append("\n")
        elif name == "p":
            chunks.append("\n")

    walk(root)
    return "".join(chunks)


def extract_docx(path: Path) -> Extraction:
    parts: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            if name.startswith("word/") and name.endswith(".xml"):
                parts.append((name, archive.read(name)))
    parts.sort(key=lambda item: (item[0] != "word/document.xml", item[0]))
    text = "\n".join(_docx_part_text(data) for _, data in parts)
    if not text.strip():
        raise ExtractionError(tr("docx_no_text"))
    return Extraction(text=text)


def extract_doc(path: Path) -> Extraction:
    try:
        from legacy_doc import extract_text
    except ImportError as error:
        raise ExtractionError(tr("doc_dependency")) from error
    result = extract_text(path.read_bytes())
    warnings = tuple(getattr(result, "warnings", ()) or ())
    if not result.text.strip():
        raise ExtractionError(tr("doc_no_text"))
    return Extraction(text=result.text, warnings=warnings)


def extract_rtf(path: Path) -> Extraction:
    try:
        from striprtf.striprtf import rtf_to_text
    except ImportError as error:
        raise ExtractionError(tr("rtf_dependency")) from error
    raw, _ = read_text(path)
    text = rtf_to_text(raw)
    if not text.strip():
        raise ExtractionError(tr("rtf_no_text"))
    warning_list: list[str] = []
    if not re.search(r"\\(?:highlight|chcbpat)\\d+", raw, re.IGNORECASE):
        warning_list.append(tr("rtf_no_highlight"))
    if re.search(r"\\(?:shppict|pict|object)\b", raw, re.IGNORECASE):
        warning_list.append(tr("rtf_graphics"))
    return Extraction(text=text, warnings=tuple(warning_list), marked=_rtf_highlights(raw, text))


def _rtf_highlights(raw: str, text: str) -> tuple[dict[str, Any], ...]:
    parsed_text, spans = _rtf_to_text_with_highlights(raw)
    if parsed_text != text:
        return ()

    result: list[dict[str, Any]] = []
    for start, end in spans:
        value = text[start:end]
        if not value.strip():
            continue
        result.append({
            "start": start,
            "end": end,
            "value": value,
            "type": _guess_marked_type(value, text, start),
            "name": "RTF highlighted text",
            "priority": -1,
        })
    return tuple(result)


def _rtf_to_text_with_highlights(raw: str) -> tuple[str, list[tuple[int, int]]]:
    text, chunks = _rtf_text_chunks(raw)
    spans: list[tuple[int, int]] = []
    offset = 0
    active_start: int | None = None
    for value, marked, _, _ in chunks:
        if marked and active_start is None:
            active_start = offset
        if not marked and active_start is not None:
            spans.append((active_start, offset))
            active_start = None
        offset += len(value)
    if active_start is not None:
        spans.append((active_start, offset))
    return text, spans


def _rtf_text_chunks(raw: str) -> tuple[str, list[tuple[str, bool, int, int]]]:
    from striprtf.striprtf import (
        FONTTABLE,
        HYPERLINKS,
        PATTERN,
        charset_map,
        destinations,
        font_table_group,
        remove_pict_groups,
        specialchars,
    )

    raw = remove_pict_groups(raw)
    raw = re.sub(HYPERLINKS, r"\1(\2)", raw)
    fonttbl = {
        font_id: {"charset": fcharset, "encoding": charset_map.get(int(fcharset), "cp1252")}
        for font_id, fcharset, _ in FONTTABLE.findall(font_table_group(raw))
    }
    stack: list[tuple[int, bool, bool, int]] = []
    ucskip = 1
    curskip = 0
    ignorable = False
    suppress_output = False
    highlight = 0
    current_font: str | None = None
    default_font: str | None = None
    depth = 0
    in_document = False
    chunks: list[tuple[str, bool, int, int]] = []

    def emit(value: str, raw_start: int, raw_end: int) -> None:
        if value and not ignorable and not suppress_output:
            chunks.append((value, highlight == 7, raw_start, raw_end))

    for match in PATTERN.finditer(raw):
        word, arg, hex_value, char, brace, tchar = match.groups()
        if brace:
            curskip = 0
            if brace == "{":
                depth += 1
                in_document = True
                stack.append((ucskip, ignorable, suppress_output, highlight))
            else:
                depth -= 1
                if stack:
                    ucskip, ignorable, suppress_output, highlight = stack.pop()
                else:
                    ignorable = True
                    ucskip = 0
                if in_document and depth <= 0:
                    break
        elif char:
            curskip = 0
            if char in specialchars and not ignorable:
                emit(specialchars[char], match.start(), match.end())
        elif word:
            curskip = 0
            if word in destinations:
                ignorable = True
            elif word == "ansicpg":
                pass
            elif ignorable or suppress_output:
                pass
            elif word == "fonttbl":
                suppress_output = True
            elif word == "colortbl":
                suppress_output = True
            elif word == "deff":
                default_font = arg
            elif word == "f":
                current_font = arg
            elif word == "highlight":
                highlight = int(arg or 0)
            elif word == "uc":
                ucskip = int(arg or 1)
            elif word == "u":
                value = int(arg or 0)
                if value < 0:
                    value += 0x10000
                emit(chr(value), match.start(), match.end())
                curskip = ucskip
            elif word in specialchars:
                emit(specialchars[word], match.start(), match.end())
        elif hex_value:
            if curskip > 0:
                curskip -= 1
            elif not ignorable:
                encoding = fonttbl.get(current_font, {}).get("encoding", "cp1251")
                emit(bytes.fromhex(hex_value).decode(encoding, errors="replace"), match.start(), match.end())
        elif tchar:
            if curskip > 0:
                curskip -= 1
            else:
                emit(tchar, match.start(), match.end())

    text = "".join(value for value, _, _, _ in chunks)
    return text, chunks


def replace_rtf(raw: str, source_text: str, changes: list[tuple[int, int, str]]) -> str:
    parsed_text, chunks = _rtf_text_chunks(raw)
    if parsed_text != source_text:
        raise ExtractionError(tr("rtf_mapping"))
    if not changes:
        return remove_rtf_graphics(raw)
    if any(start < 0 or end > len(chunks) or start >= end for start, end, _ in changes):
        raise ExtractionError(tr("rtf_changes"))
    patches: list[tuple[int, int, str]] = []
    for start, end, replacement in changes:
        raw_start = chunks[start][2]
        raw_end = chunks[end - 1][3]
        escaped = replacement.replace("\\", r"\\").replace("{", r"\{").replace("}", r"\}")
        patches.append((raw_start, raw_end, escaped))
    for raw_start, raw_end, replacement in sorted(patches, reverse=True):
        raw = raw[:raw_start] + replacement + raw[raw_end:]
    return remove_rtf_graphics(raw)


def remove_rtf_graphics(raw: str) -> str:
    starts = list(re.finditer(r"\{\\(?:\*\\)?(?:shppict|pict|object)\b", raw, re.IGNORECASE))
    ranges: list[tuple[int, int]] = []
    for match in starts:
        depth = 0
        index = match.start()
        while index < len(raw):
            char = raw[index]
            if char == "\\":
                index += 2
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    ranges.append((match.start(), index + 1))
                    break
            index += 1
    kept: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if kept and end <= kept[-1][1]:
            continue
        kept.append((start, end))
    for start, end in reversed(kept):
        raw = raw[:start] + raw[end:]
    return raw


def _guess_marked_type(value: str, text: str, start: int) -> str:
    before = text[max(0, start - 80) : start]
    if re.search(r"(?i)(?:г\.|гор\.|город|обл\.|край|р-н)", before):
        return "CITY"
    if re.search(r"(?i)(?:адрес|ул\.|улиц|дом|д\.|квартир|кв\.)", before):
        return "ADDRESS"
    if re.search(r"(?i)(?:ООО|АО|ПАО|ОАО|ЗАО|ИП|АКБ|банк|компани|организаци|университет|министерств|администраци|фонд)", value):
        return "ORGANIZATION"
    if re.search(r"(?i)(?:\b(?:в|из|к|по|на|под|около)\s+)$", before):
        return "CITY"
    if len(re.findall(r"[А-ЯЁA-Z][а-яёa-z-]+", value)) >= 2:
        return "PERSON"
    return "SENSITIVE"


def extract_pdf(path: Path) -> Extraction:
    try:
        from pypdf import PdfReader
    except ImportError as error:
        raise ExtractionError(tr("pdf_dependency")) from error
    reader = PdfReader(str(path))
    pages = [(page.extract_text() or "").strip() for page in reader.pages]
    text = "\n\n".join(page for page in pages if page)
    empty_pages = sum(not page for page in pages)
    if not text.strip():
        raise ExtractionError(tr("pdf_scan"))
    warnings = ()
    if empty_pages:
        warnings = (tr("pdf_empty_pages", count=empty_pages),)
    return Extraction(text=text, warnings=warnings)


def extract(path: Path) -> tuple[Extraction, str]:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".json", ".csv"}:
        text, encoding = read_text(path)
        return Extraction(text=text), encoding
    if suffix == ".docx":
        return extract_docx(path), "utf-8"
    if suffix == ".doc":
        return extract_doc(path), "utf-8"
    if suffix == ".rtf":
        return extract_rtf(path), "utf-8"
    if suffix == ".pdf":
        return extract_pdf(path), "utf-8"
    raise ExtractionError(tr("unsupported_format", value=suffix or "<no extension>"))


def validate_json_if_needed(path: Path, text: str) -> None:
    if path.suffix.lower() == ".json":
        json.loads(text)
