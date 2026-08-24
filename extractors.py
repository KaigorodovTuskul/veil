"""Text extraction adapters used by the local anonymizer."""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree


class ExtractionError(Exception):
    """The file cannot safely be converted to text."""


@dataclass(frozen=True)
class Extraction:
    text: str
    warnings: tuple[str, ...] = ()


def read_text(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    encodings = ("utf-8-sig", "utf-8", "cp1251", "latin-1") if data.startswith(b"\xef\xbb\xbf") else ("utf-8", "cp1251", "latin-1")
    for encoding in encodings:
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise UnicodeError(f"Не удалось определить кодировку: {path}")


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
        raise ExtractionError("DOCX не содержит извлекаемого текста")
    return Extraction(text=text)


def extract_doc(path: Path) -> Extraction:
    try:
        from legacy_doc import extract_text
    except ImportError as error:
        raise ExtractionError("Для DOC нужен пакет legacy-doc: установите requirements.txt") from error
    result = extract_text(path.read_bytes())
    warnings = tuple(getattr(result, "warnings", ()) or ())
    if not result.text.strip():
        raise ExtractionError("DOC не содержит извлекаемого текста или зашифрован")
    return Extraction(text=result.text, warnings=warnings)


def extract_rtf(path: Path) -> Extraction:
    try:
        from striprtf.striprtf import rtf_to_text
    except ImportError as error:
        raise ExtractionError("Для RTF нужен пакет striprtf: установите requirements.txt") from error
    raw, _ = read_text(path)
    text = rtf_to_text(raw)
    if not text.strip():
        raise ExtractionError("RTF не содержит извлекаемого текста")
    return Extraction(text=text)


def extract_pdf(path: Path) -> Extraction:
    try:
        from pypdf import PdfReader
    except ImportError as error:
        raise ExtractionError("Для PDF нужен пакет pypdf: установите requirements.txt") from error
    reader = PdfReader(str(path))
    pages = [(page.extract_text() or "").strip() for page in reader.pages]
    text = "\n\n".join(page for page in pages if page)
    empty_pages = sum(not page for page in pages)
    if not text.strip():
        raise ExtractionError("PDF похож на скан или содержит только изображения; OCR пока не включён")
    warnings = ()
    if empty_pages:
        warnings = (f"PDF: {empty_pages} страниц без извлекаемого текста; данные на них могут быть изображениями",)
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
    raise ExtractionError(f"Формат {suffix or '<без расширения>'} пока не поддерживается")


def validate_json_if_needed(path: Path, text: str) -> None:
    if path.suffix.lower() == ".json":
        json.loads(text)
