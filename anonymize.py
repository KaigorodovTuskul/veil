#!/usr/bin/env python3
"""Interactive, local PII replacement with input/output folder mode."""

from __future__ import annotations

import argparse
import builtins
import csv
import json
import re
import sys
from pathlib import Path
from typing import Any

from extractors import ExtractionError, _rtf_text_chunks, extract, read_text as read_extracted_text, replace_rtf, validate_json_if_needed
from i18n import LANGUAGES, entity_label, language, set_language, tr

SUPPORTED = {".txt", ".json", ".csv", ".doc", ".docx", ".rtf", ".pdf"}
TEXT_FORMATS = {".txt", ".json", ".csv", ".rtf"}
MATCH_FLAGS = 0
SCRIPT_DIR = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent
CONFIG_DIR = SCRIPT_DIR / "config"
USER_KEYWORDS_PATH = CONFIG_DIR / "user_keywords.csv"
IGNORE_KEYWORDS_PATH = CONFIG_DIR / "ignore_keywords.txt"
USER_KEYWORD_TYPES = {
    "PERSON": "PERSON",
    "NAME": "PERSON",
    "ADDRESS": "ADDRESS",
    "CITY": "CITY",
    "REGION": "REGION",
    "COUNTRY": "COUNTRY",
    "ORG": "ORGANIZATION",
    "ORGANIZATION": "ORGANIZATION",
    "COMPANY": "ORGANIZATION",
    "SENSITIVE": "SENSITIVE",
}
PERSON_STOP_WORDS = {
    "банк", "банка", "департамент", "департамента", "договор", "комиссия", "комиссии",
    "председатель", "председателя", "правление", "правления", "россия", "россии",
    "российская", "российской", "федерация", "федерации", "республика", "республики",
}
ORGANIZATION_STOP_WORDS = {"группа", "группы", "договор", "департамент", "департамента", "комиссия", "комиссии"}
ENGLISH_GIVEN_NAMES = {
    "alex", "alice", "anna", "charles", "david", "daniel", "edward", "elizabeth", "emily", "george",
    "henry", "james", "john", "joseph", "julia", "karen", "laura", "linda", "maria", "michael",
    "nancy", "natalie", "nicholas", "oliver", "patricia", "paul", "peter", "richard", "robert", "sarah",
    "steven", "susan", "thomas", "william",
}
LEGAL_FORM_PATTERN = re.compile(r"(?i)(?<![\w-])(?:ООО|АО|ПАО|ОАО|ЗАО|ИП|АКБ|LLC|LTD|INC)(?![\w-])")


def load_rules() -> list[dict[str, Any]]:
    with (SCRIPT_DIR / "patterns.json").open(encoding="utf-8") as file:
        return json.load(file)


def _normal_form(value: str) -> str:
    value = value.translate(str.maketrans({"\u00a0": " ", "\u200b": " ", "\ufeff": "", "ё": "е", "Ё": "Е"}))
    return re.sub(r"\s+", " ", value).strip().casefold()


def _keyword_pattern(value: str) -> re.Pattern[str]:
    parts = [part for part in re.split(r"\s+", value.strip()) if part]
    body = r"[\s\u00a0]+".join(re.escape(part) for part in parts)
    return re.compile(rf"(?<![\w]){body}(?![\w])", re.IGNORECASE)


def load_user_keywords() -> dict[str, Any]:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not USER_KEYWORDS_PATH.exists():
        USER_KEYWORDS_PATH.write_text("type;keyword;aliases\n", encoding="utf-8")
    if not IGNORE_KEYWORDS_PATH.exists():
        IGNORE_KEYWORDS_PATH.write_text("# One normalized word or phrase per line\n", encoding="utf-8")

    entries: list[dict[str, Any]] = []
    with USER_KEYWORDS_PATH.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file, delimiter=";")
        for line_number, row in enumerate(reader, 2):
            keyword = (row.get("keyword") or "").strip()
            if not keyword or keyword.startswith("#"):
                continue
            entity_type = USER_KEYWORD_TYPES.get((row.get("type") or "SENSITIVE").strip().upper())
            if entity_type is None:
                raise ValueError(f"config/user_keywords.csv line {line_number}: unknown type")
            variants = [keyword]
            variants.extend(alias.strip() for alias in (row.get("aliases") or "").split("|") if alias.strip())
            entries.append({
                "type": entity_type,
                "keyword": keyword,
                "patterns": tuple(_keyword_pattern(variant) for variant in variants),
            })

    ignored = {
        _normal_form(line)
        for line in IGNORE_KEYWORDS_PATH.read_text(encoding="utf-8-sig").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    return {"entries": tuple(entries), "ignored": ignored}


def read_text(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    encodings = ("utf-8-sig", "utf-8", "cp1251", "latin-1") if data.startswith(b"\xef\xbb\xbf") else ("utf-8", "cp1251", "latin-1")
    for encoding in encodings:
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise UnicodeError(tr("encoding_error", value=path))


def write_text(path: Path, text: str, encoding: str) -> None:
    path.write_bytes(text.encode(encoding))


def find_candidates(text: str, rules: list[dict[str, Any]], user_keywords: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    text = text.translate(str.maketrans({"\u00a0": " ", "\u200b": " ", "\ufeff": " ", "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-"}))
    candidates: list[dict[str, Any]] = []
    user_keywords = user_keywords or {"entries": (), "ignored": set()}
    for entry in user_keywords["entries"]:
        for pattern in entry["patterns"]:
            for match in pattern.finditer(text):
                value = match.group(0)
                if _normal_form(value) not in user_keywords["ignored"]:
                    candidates.append({
                        "start": match.start(),
                        "end": match.end(),
                        "value": value,
                        "type": entry["type"],
                        "name": "User dictionary",
                        "priority": -1,
                        "key": _normal_form(entry["keyword"]),
                    })
    for priority, rule in enumerate(rules):
        for match in re.compile(rule["regex"], MATCH_FLAGS).finditer(text):
            group = rule.get("value_group")
            start, end = match.span(group or 0)
            value = text[start:end]
            if rule["type"] == "ORGANIZATION":
                legal_forms = list(LEGAL_FORM_PATTERN.finditer(value))
                if legal_forms and legal_forms[-1].start() > 0:
                    end = start + legal_forms[-1].end()
                    value = text[start:end]
            if rule["type"] == "ADDRESS":
                trimmed = value.rstrip(" \t.,;:")
                end -= len(value) - len(trimmed)
                value = trimmed
            if rule["name"] == "Person surname and name" and value.isupper():
                continue
            words = {word.casefold() for word in re.findall(r"[A-Za-zА-ЯЁа-яё-]+", value)}
            if rule["name"] in {"English person full name", "English person uppercase full name"} and not words & ENGLISH_GIVEN_NAMES:
                continue
            if value.strip() and _normal_form(value) not in user_keywords["ignored"] and not (
                rule["type"] == "PERSON" and words & PERSON_STOP_WORDS
                or rule["type"] == "ORGANIZATION" and len(words) == 1 and words & ORGANIZATION_STOP_WORDS
            ):
                candidates.append({
                    "start": start,
                    "end": end,
                    "value": value,
                    "type": rule["type"],
                    "name": rule["name"],
                    "priority": priority,
                })

    candidates.sort(key=lambda item: (item["start"], -(item["end"] - item["start"]), item["priority"]))
    selected: list[dict[str, Any]] = []
    for candidate in candidates:
        if any(candidate["start"] < other["end"] and other["start"] < candidate["end"] for other in selected):
            continue
        selected.append(candidate)
    return sorted(selected, key=lambda item: item["start"])


def context(text: str, start: int, end: int, width: int = 55) -> str:
    left = max(0, start - width)
    right = min(len(text), end + width)
    snippet = text[left:right].replace("\n", " ").replace("\r", " ")
    marker_start = start - left
    marker_end = marker_start + end - start
    return f"{snippet[:marker_start]}>>> {snippet[marker_start:marker_end]} <<<{snippet[marker_end:]}"


def token_for(entity_type: str, counters: dict[str, int], prefix: str = "") -> str:
    counters[entity_type] = counters.get(entity_type, 0) + 1
    return f"{{{{{prefix}{entity_type}_{counters[entity_type]}}}}}"


def ask(candidate: dict[str, Any], text: str) -> str:
    print(f"\n{tr('found', label=entity_label(candidate['type']), value=candidate['value'])}")
    print(tr("context", value=context(text, candidate["start"], candidate["end"])))
    print(tr("choices"))
    while True:
        answer = input("> ").strip()
        if answer in {"1", "2", "3", "4"}:
            return answer
        print(tr("invalid_choice"))


def anonymize(text: str, rules: list[dict[str, Any]], marked: tuple[dict[str, Any], ...] = (), auto: bool = False, token_prefix: str = "", user_keywords: dict[str, Any] | None = None) -> tuple[str, dict[str, str], int, list[tuple[int, int, str]]]:
    candidates = find_candidates(text, rules, user_keywords) + list(marked)
    candidates.sort(key=lambda item: (item["start"], -(item["end"] - item["start"]), item["priority"]))
    selected: list[dict[str, Any]] = []
    for candidate in candidates:
        if any(candidate["start"] < other["end"] and other["start"] < candidate["end"] for other in selected):
            continue
        selected.append(candidate)
    candidates = selected
    replacements: dict[Any, str] = {}
    original_values: dict[Any, str] = {}
    decisions: dict[Any, str] = {}
    counters: dict[str, int] = {}
    changes: list[tuple[int, int, str]] = []

    for candidate in candidates:
        key = candidate.get("key", (candidate["type"], candidate["value"]))
        decision = decisions.get(key)
        token = replacements.get(key)
        if decision is None:
            decision = "1" if auto else ask(candidate, text)
            if decision == "4":
                raise KeyboardInterrupt
            decisions[key] = "replace" if decision in {"1", "3"} else "skip"
        if decisions[key] == "replace":
            if token is None:
                token = token_for(candidate["type"], counters, token_prefix)
                replacements[key] = token
                original_values[key] = candidate["value"]
            changes.append((candidate["start"], candidate["end"], token))

    for start, end, replacement in reversed(changes):
        text = text[:start] + replacement + text[end:]
    return text, {token: original_values[key] for key, token in replacements.items()}, len(changes), changes


def restore(text: str, mapping: dict[str, str]) -> str:
    for token, value in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        text = text.replace(token, value)
    return text


def output_path(path: Path, suffix: str) -> Path:
    return path.with_name(f"{path.stem}{suffix}{path.suffix}")


def process(path: Path, rules: list[dict[str, Any]], user_keywords: dict[str, Any], output_dir: Path, file_number: int, auto: bool = False) -> None:
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError(tr("unsupported_format", value=path.suffix or "<no extension>"))
    extraction, encoding = extract(path)
    text = extraction.text
    for warning in extraction.warnings:
        print(tr("warning", value=warning), file=sys.stderr)
    validate_json_if_needed(path, text)
    anonymized, mapping, count, changes = anonymize(text, rules, extraction.marked, auto=auto, user_keywords=user_keywords)
    safe_stem, filename_mapping, filename_count, _ = anonymize(path.stem, rules, auto=auto, token_prefix="FILENAME_", user_keywords=user_keywords)
    mapping.update(filename_mapping)
    for token in filename_mapping:
        safe_stem = safe_stem.replace(token, "")
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = re.sub(r"[ \t]{2,}", " ", safe_stem).strip(" ._-\t") or f"document_{file_number:03d}"
    result = output_dir / (f"{safe_stem}.anonymized{path.suffix}" if path.suffix.lower() in TEXT_FORMATS else f"{safe_stem}{path.suffix}.anonymized.txt")
    map_path = output_dir / f"{safe_stem}{path.suffix}.mapping.json"
    if path.suffix.lower() == ".rtf":
        raw, rtf_encoding = read_extracted_text(path)
        write_text(result, replace_rtf(raw, text, changes), rtf_encoding)
    else:
        write_text(result, anonymized, encoding)
    mapping_payload = dict(mapping)
    mapping_payload["_veil"] = {"original_filename": path.name}
    map_path.write_text(json.dumps(mapping_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\n{tr('done', replaced=count + filename_count, found=len(find_candidates(text, rules, user_keywords)) + len(find_candidates(path.stem, rules, user_keywords)))}")
    print(tr("file", value=result))
    print(tr("mapping", value=map_path))
    print(tr("filename_hidden", value=result.name))


def restore_file(path: Path, map_path: Path) -> None:
    text, encoding = read_text(path)
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    mapping.pop("_veil", None)
    if path.suffix.lower() == ".rtf":
        mapping = {
            token.replace("\\", r"\\").replace("{", r"\{").replace("}", r"\}"): value
            for token, value in mapping.items()
        }
    result = output_path(path, ".restored")
    write_text(result, restore(text, mapping), encoding)
    print(tr("restored", value=result))


def anonymize_with_answers(text: str, rules: list[dict[str, Any]], answers: list[str]) -> tuple[str, dict[str, str], int, list[tuple[int, int, str]]]:
    iterator = iter(answers)
    original_input = builtins.input
    try:
        builtins.input = lambda _prompt="": next(iterator)
        return anonymize(text, rules)
    finally:
        builtins.input = original_input


def self_test() -> None:
    rules = [
        {"name": "Email", "type": "EMAIL", "regex": r"(?<![\w.-])[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}(?![\w.-])"},
        {"name": "ФИО", "type": "PERSON", "regex": r"ФИО:\s*(?P<value>[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+)", "value_group": "value"},
    ]
    source = "ФИО: Иванов Иван, email ivan@example.com; ещё раз ivan@example.com"
    result, mapping, count, _ = anonymize_with_answers(source, rules, ["3", "1"])
    assert result == "ФИО: {{PERSON_1}}, email {{EMAIL_1}}; ещё раз {{EMAIL_1}}"
    assert mapping == {"{{PERSON_1}}": "Иванов Иван", "{{EMAIL_1}}": "ivan@example.com"}
    assert count == 3
    assert restore(result, mapping) == source
    auto_result, auto_mapping, auto_count, _ = anonymize(source, rules, auto=True)
    assert auto_result == result
    assert auto_mapping == mapping
    assert auto_count == 3
    production_rules = load_rules()
    uppercase = "ФИО: ИВАНОВ ИВАН, ООО ПУПКИНБАНК"
    uppercase_candidates = find_candidates(uppercase, production_rules)
    assert {candidate["value"] for candidate in uppercase_candidates} == {"ИВАНОВ ИВАН", "ООО ПУПКИНБАНК"}
    variants = find_candidates("Пупкинбанк; Пуп кинбанк", production_rules)
    assert {candidate["value"] for candidate in variants} == {"Пупкинбанк", "Пуп кинбанк"}
    extended_persons = find_candidates("Иванову Николаю Николаевичу; John Smith; Smith J.; JOHN SMITH", production_rules)
    assert {candidate["value"] for candidate in extended_persons} == {
        "Иванову Николаю Николаевичу", "John Smith", "Smith J.", "JOHN SMITH"
    }
    assert {candidate["value"] for candidate in find_candidates("Ромашкабанк", production_rules)} == {"Ромашкабанк"}
    assert {candidate["value"] for candidate in find_candidates("АКБ «Пупкинбанк» АО НА 2026 ГОД", production_rules)} == {"АКБ «Пупкинбанк» АО"}
    filename_result, filename_mapping, _, _ = anonymize("1011-ПЛ АКБ Пупкинбанк", production_rules, auto=True, token_prefix="FILENAME_")
    assert filename_result == "1011-ПЛ {{FILENAME_ORGANIZATION_1}}"
    assert filename_mapping == {"{{FILENAME_ORGANIZATION_1}}": "АКБ Пупкинбанк"}
    safe_filename = re.sub(r"[ \t]{2,}", " ", filename_result.replace("{{FILENAME_ORGANIZATION_1}}", "")).strip(" ._-\t")
    assert safe_filename == "1011-ПЛ"
    assert {candidate["value"] for candidate in find_candidates("С.А. Миллер; компании PricewaterhouseCoopers", production_rules)} == {"С.А. Миллер", "PricewaterhouseCoopers"}
    assert {candidate["value"] for candidate in find_candidates("Банк России и политика Банка России", production_rules)} == {"России"}
    assert {candidate["value"] for candidate in find_candidates("ЯКУТСК; Якутске; Республика Саха (Якутия)", production_rules)} == {"ЯКУТСК", "Якутске", "Республика Саха (Якутия)"}
    assert {candidate["value"] for candidate in find_candidates("Москва; Москве; Москвы; г. Москва", production_rules)} == {"Москва", "Москве", "Москвы"}
    address_candidates = find_candidates("Адрес: г. Якутск, ул. Ленина, д. 10, кв. 5. Проживает по адресу: Москва, проспект Мира, дом 20.", production_rules)
    assert {candidate["value"] for candidate in address_candidates if candidate["type"] == "ADDRESS"} == {
        "г. Якутск, ул. Ленина, д. 10, кв. 5",
        "Москва, проспект Мира, дом 20",
    }
    negative_candidates = find_candidates(
        "СТРАТЕГИЧЕСКИЙ РИСК; ОБЪЕМОВ КРЕДИТНОГО ПОРТФЕЛЯ; проспекты эмиссии обыкновенных акций",
        production_rules,
    )
    assert not {candidate["value"] for candidate in negative_candidates if candidate["type"] in {"PERSON", "ADDRESS"}}
    unicode_rtf = r"{\rtf1\ansi\u1040?\u1050?}"
    assert _rtf_text_chunks(unicode_rtf)[0] == "АК"
    assert replace_rtf(unicode_rtf, "АК", [(0, 2, "{{PERSON_1}}")]) == r"{\rtf1\ansi\{\{PERSON_1\}\}}"
    footer_rtf = r"{\rtf1\ansi{\footerf Footer Company}\par Main}"
    footer_text = _rtf_text_chunks(footer_rtf)[0]
    assert "Footer Company" in footer_text
    footer_start = footer_text.index("Company")
    assert "Footer" in replace_rtf(footer_rtf, footer_text, [(footer_start, footer_start + 7, "{{ORGANIZATION_1}}")])
    sample_rtf = replace_rtf(r"{\rtf1\ansi Test\par}", "Test\n", [(0, 4, "{{PERSON_1}}")])
    assert sample_rtf == r"{\rtf1\ansi \{\{PERSON_1\}\}\par}"
    dictionary = {
        "entries": ({
            "type": "ORGANIZATION",
            "keyword": 'ООО "Ромашка"',
            "patterns": (_keyword_pattern('ООО "Ромашка"'), _keyword_pattern("Ромашка")),
        },),
        "ignored": {_normal_form("банк")},
    }
    dictionary_candidates = find_candidates('ООО "РОМАШКА" и Ромашка; банк', production_rules, dictionary)
    assert {candidate["value"] for candidate in dictionary_candidates} == {'ООО "РОМАШКА"', "Ромашка"}
    dictionary_result, dictionary_mapping, _, _ = anonymize(
        'ООО "РОМАШКА" и Ромашка; банк', production_rules, auto=True, user_keywords=dictionary
    )
    assert dictionary_result == '{{ORGANIZATION_1}} и {{ORGANIZATION_1}}; банк'
    assert dictionary_mapping == {'{{ORGANIZATION_1}}': 'ООО "РОМАШКА"'}
    print(tr("self_test"))


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    bootstrap = argparse.ArgumentParser(add_help=False)
    bootstrap.add_argument("--lang", choices=LANGUAGES)
    bootstrap_args, _ = bootstrap.parse_known_args()
    set_language(bootstrap_args.lang)

    parser = argparse.ArgumentParser(description=tr("description"))
    parser.add_argument("files", nargs="*", type=Path, help=tr("files_help"))
    parser.add_argument("--restore", nargs=2, metavar=("FILE", "MAP"), help=tr("restore_help"))
    parser.add_argument("--self-test", action="store_true", help=tr("self_test_help"))
    parser.add_argument("--auto", action="store_true", help=tr("auto_help"))
    parser.add_argument("--lang", choices=LANGUAGES, default=language(), help=tr("lang_help"))
    args = parser.parse_args()
    set_language(args.lang)

    if args.self_test:
        self_test()
        return 0
    if args.restore:
        restore_file(Path(args.restore[0]), Path(args.restore[1]))
        return 0
    rules = load_rules()
    user_keywords = load_user_keywords()
    print(tr("user_dictionary", keywords=len(user_keywords["entries"]), ignored=len(user_keywords["ignored"])))
    input_dir = SCRIPT_DIR / "input"
    output_dir = SCRIPT_DIR / "output"
    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)
    files = args.files or sorted(
        (path for path in input_dir.iterdir() if path.is_file() and path.suffix.lower() in SUPPORTED),
        key=lambda path: path.name.lower(),
    )
    if not files:
        print(tr("empty_input", value=input_dir))
        print(tr("drop_files"))
        return 0
    print(tr("processing", count=len(files), value=output_dir))
    errors = 0
    for file_number, path in enumerate(files, 1):
        try:
            process(path, rules, user_keywords, output_dir, file_number, auto=args.auto)
        except KeyboardInterrupt:
            print(f"\n{tr('stopped')}")
            return 130
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError, ExtractionError) as error:
            print(tr("error", value=error), file=sys.stderr)
            error_file = output_dir / f"document_{file_number:03d}{path.suffix}.error.txt"
            error_file.write_text(str(error) + "\n", encoding="utf-8")
            print(tr("error_file", value=error_file), file=sys.stderr)
            errors += 1
    if errors:
        print(tr("batch_errors", count=errors), file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
