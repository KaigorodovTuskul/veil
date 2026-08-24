#!/usr/bin/env python3
"""Interactive, local PII replacement with input/output folder mode."""

from __future__ import annotations

import argparse
import builtins
import json
import re
import sys
from pathlib import Path
from typing import Any

from extractors import ExtractionError, extract, validate_json_if_needed

SUPPORTED = {".txt", ".json", ".csv", ".doc", ".docx", ".rtf", ".pdf"}
TEXT_FORMATS = {".txt", ".json", ".csv"}
SCRIPT_DIR = Path(sys.executable if getattr(sys, "frozen", False) else __file__).resolve().parent


def load_rules() -> list[dict[str, Any]]:
    with (SCRIPT_DIR / "patterns.json").open(encoding="utf-8") as file:
        return json.load(file)


def read_text(path: Path) -> tuple[str, str]:
    data = path.read_bytes()
    encodings = ("utf-8-sig", "utf-8", "cp1251", "latin-1") if data.startswith(b"\xef\xbb\xbf") else ("utf-8", "cp1251", "latin-1")
    for encoding in encodings:
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise UnicodeError(f"Не удалось определить кодировку: {path}")


def write_text(path: Path, text: str, encoding: str) -> None:
    path.write_bytes(text.encode(encoding))


def find_candidates(text: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for priority, rule in enumerate(rules):
        for match in re.compile(rule["regex"]).finditer(text):
            group = rule.get("value_group")
            start, end = match.span(group or 0)
            value = text[start:end]
            if value.strip():
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


def token_for(entity_type: str, counters: dict[str, int]) -> str:
    counters[entity_type] = counters.get(entity_type, 0) + 1
    return f"{{{{{entity_type}_{counters[entity_type]}}}}}"


def ask(candidate: dict[str, Any], text: str) -> str:
    print(f"\nНайдено [{candidate['name']}]: {candidate['value']}")
    print(f"Контекст: {context(text, candidate['start'], candidate['end'])}")
    print("1 — заменить   2 — пропустить   3 — заменить все такие   4 — выйти")
    while True:
        answer = input("> ").strip()
        if answer in {"1", "2", "3", "4"}:
            return answer
        print("Введите 1, 2, 3 или 4.")


def anonymize(text: str, rules: list[dict[str, Any]]) -> tuple[str, dict[str, str], int]:
    candidates = find_candidates(text, rules)
    replacements: dict[tuple[str, str], str] = {}
    decisions: dict[tuple[str, str], str] = {}
    counters: dict[str, int] = {}
    changes: list[tuple[int, int, str]] = []

    for candidate in candidates:
        key = (candidate["type"], candidate["value"])
        decision = decisions.get(key)
        token = replacements.get(key)
        if decision is None:
            decision = ask(candidate, text)
            if decision == "4":
                raise KeyboardInterrupt
            decisions[key] = "replace" if decision in {"1", "3"} else "skip"
        if decisions[key] == "replace":
            if token is None:
                token = token_for(candidate["type"], counters)
                replacements[key] = token
            changes.append((candidate["start"], candidate["end"], token))

    for start, end, replacement in reversed(changes):
        text = text[:start] + replacement + text[end:]
    return text, {token: value for (_, value), token in replacements.items()}, len(changes)


def restore(text: str, mapping: dict[str, str]) -> str:
    for token, value in sorted(mapping.items(), key=lambda item: len(item[0]), reverse=True):
        text = text.replace(token, value)
    return text


def output_path(path: Path, suffix: str) -> Path:
    return path.with_name(f"{path.stem}{suffix}{path.suffix}")


def process(path: Path, rules: list[dict[str, Any]], output_dir: Path) -> None:
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError(f"Формат {path.suffix or '<без расширения>'} пока не поддерживается")
    extraction, encoding = extract(path)
    text = extraction.text
    for warning in extraction.warnings:
        print(f"ВНИМАНИЕ: {warning}", file=sys.stderr)
    validate_json_if_needed(path, text)
    anonymized, mapping, count = anonymize(text, rules)
    output_dir.mkdir(parents=True, exist_ok=True)
    result = output_dir / (f"{path.stem}.anonymized{path.suffix}" if path.suffix.lower() in TEXT_FORMATS else f"{path.name}.anonymized.txt")
    map_path = output_dir / f"{path.name}.mapping.json"
    write_text(result, anonymized, encoding)
    map_path.write_text(json.dumps(mapping, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"\nГотово: заменено {count}, найдено всего {len(find_candidates(text, rules))}")
    print(f"Файл: {result}")
    print(f"Карта замен: {map_path} — храните её отдельно от очищенного файла")


def restore_file(path: Path, map_path: Path) -> None:
    text, encoding = read_text(path)
    mapping = json.loads(map_path.read_text(encoding="utf-8"))
    result = output_path(path, ".restored")
    write_text(result, restore(text, mapping), encoding)
    print(f"Восстановлено: {result}")


def anonymize_with_answers(text: str, rules: list[dict[str, Any]], answers: list[str]) -> tuple[str, dict[str, str], int]:
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
    result, mapping, count = anonymize_with_answers(source, rules, ["3", "1"])
    assert result == "ФИО: {{PERSON_1}}, email {{EMAIL_1}}; ещё раз {{EMAIL_1}}"
    assert mapping == {"{{PERSON_1}}": "Иванов Иван", "{{EMAIL_1}}": "ivan@example.com"}
    assert count == 3
    assert restore(result, mapping) == source
    print("self-test: OK")


def main() -> int:
    parser = argparse.ArgumentParser(description="Интерактивная замена чувствительных данных")
    parser.add_argument("files", nargs="*", type=Path, help="TXT, JSON, CSV, DOC, DOCX, RTF или PDF")
    parser.add_argument("--restore", nargs=2, metavar=("FILE", "MAP"), help="восстановить файл по карте замен")
    parser.add_argument("--self-test", action="store_true", help="запустить встроенную проверку")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return 0
    if args.restore:
        restore_file(Path(args.restore[0]), Path(args.restore[1]))
        return 0
    rules = load_rules()
    input_dir = SCRIPT_DIR / "input"
    output_dir = SCRIPT_DIR / "output"
    input_dir.mkdir(exist_ok=True)
    output_dir.mkdir(exist_ok=True)
    files = args.files or sorted(
        (path for path in input_dir.iterdir() if path.is_file() and path.suffix.lower() in SUPPORTED),
        key=lambda path: path.name.lower(),
    )
    if not files:
        print(f"Input folder is empty: {input_dir}")
        print("Drop TXT, JSON, CSV, DOC, DOCX, RTF or PDF files there and run again.")
        return 0
    print(f"Processing {len(files)} file(s) into {output_dir}")
    for path in files:
        try:
            process(path, rules, output_dir)
        except KeyboardInterrupt:
            print("\nОстановлено. Исходный файл не изменён.")
            return 130
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError, ExtractionError) as error:
            print(f"Ошибка: {error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
