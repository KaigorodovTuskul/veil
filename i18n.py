"""Small built-in UI translation table; no runtime language files required."""

from __future__ import annotations

import os

LANGUAGES = ("ru", "en", "zh")
DEFAULT_LANGUAGE = "ru"
_language = DEFAULT_LANGUAGE

MESSAGES = {
    "ru": {
        "description": "Локальная интерактивная анонимизация документов",
        "files_help": "TXT, JSON, CSV, DOC, DOCX, RTF или PDF",
        "restore_help": "восстановить файл по карте замен",
        "self_test_help": "запустить встроенную проверку",
        "auto_help": "автоматически заменить все найденные значения без вопросов",
        "lang_help": "язык интерфейса: ru, en или zh",
        "found": "Найдено [{label}]: {value}",
        "context": "Контекст: {value}",
        "choices": "1 — заменить   2 — пропустить   3 — заменить все такие   4 — выйти",
        "invalid_choice": "Введите 1, 2, 3 или 4.",
        "warning": "ВНИМАНИЕ: {value}",
        "done": "Готово: заменено {replaced}, найдено всего {found}",
        "file": "Файл: {value}",
        "mapping": "Карта замен: {value} — храните её отдельно от очищенного файла",
        "filename_hidden": "Имя файла очищено; сохранённая безопасная часть: {value}",
        "restored": "Восстановлено: {value}",
        "empty_input": "Папка input пуста: {value}",
        "drop_files": "Положите туда TXT, JSON, CSV, DOC, DOCX, RTF или PDF и запустите снова.",
        "processing": "Обработка файлов: {count}; папка назначения: {value}",
        "batch_errors": "Обработка завершена с ошибками: не обработано файлов: {count}",
        "stopped": "Остановлено. Исходный файл не изменён.",
        "error": "Ошибка: {value}",
        "error_file": "Отчёт об ошибке: {value}",
        "self_test": "self-test: OK",
        "encoding_error": "Не удалось определить кодировку: {value}",
        "unsupported_format": "Формат {value} пока не поддерживается",
        "docx_no_text": "DOCX не содержит извлекаемого текста",
        "doc_dependency": "Для DOC нужен пакет legacy-doc: установите зависимости проекта",
        "doc_no_text": "DOC не содержит извлекаемого текста или зашифрован",
        "rtf_dependency": "Для RTF нужен пакет striprtf: установите зависимости проекта",
        "rtf_no_text": "RTF не содержит извлекаемого текста",
        "rtf_no_highlight": "RTF не содержит inline-маркеров жёлтой подсветки; выделения в редакторе могут быть сохранены только как стиль.",
        "rtf_graphics": "RTF содержит встроенные рисунки; в anonymized-версии все встроенные рисунки будут удалены.",
        "rtf_mapping": "Не удалось сопоставить текст RTF с исходным форматированием",
        "rtf_changes": "Некорректные позиции замены в RTF",
        "pdf_dependency": "Для PDF нужен пакет pypdf: установите зависимости проекта",
        "pdf_scan": "PDF похож на скан или содержит только изображения; OCR пока не включён",
        "pdf_empty_pages": "PDF: {count} страниц без извлекаемого текста; данные на них могут быть изображениями",
    },
    "en": {
        "description": "Local interactive document anonymizer",
        "files_help": "TXT, JSON, CSV, DOC, DOCX, RTF, or PDF",
        "restore_help": "restore a file using a replacement map",
        "self_test_help": "run the built-in check",
        "auto_help": "replace all detected values automatically without prompts",
        "lang_help": "interface language: ru, en, or zh",
        "found": "Found [{label}]: {value}",
        "context": "Context: {value}",
        "choices": "1 - replace   2 - skip   3 - replace all like this   4 - exit",
        "invalid_choice": "Enter 1, 2, 3, or 4.",
        "warning": "WARNING: {value}",
        "done": "Done: replaced {replaced}; total detected {found}",
        "file": "File: {value}",
        "mapping": "Replacement map: {value} - keep it separate from the cleaned file",
        "filename_hidden": "Filename sanitized; safe parts preserved: {value}",
        "restored": "Restored: {value}",
        "empty_input": "Input folder is empty: {value}",
        "drop_files": "Drop TXT, JSON, CSV, DOC, DOCX, RTF, or PDF files there and run again.",
        "processing": "Processing {count} file(s) into {value}",
        "batch_errors": "Processing finished with errors; failed files: {count}",
        "stopped": "Stopped. The source file was not changed.",
        "error": "Error: {value}",
        "error_file": "Error report: {value}",
        "self_test": "self-test: OK",
        "encoding_error": "Could not determine the file encoding: {value}",
        "unsupported_format": "Format {value} is not supported yet",
        "docx_no_text": "DOCX contains no extractable text",
        "doc_dependency": "DOC requires the legacy-doc package: install the project dependencies",
        "doc_no_text": "DOC contains no extractable text or is encrypted",
        "rtf_dependency": "RTF requires the striprtf package: install the project dependencies",
        "rtf_no_text": "RTF contains no extractable text",
        "rtf_no_highlight": "RTF has no inline yellow-highlight markers; editor highlights may be preserved only as styling.",
        "rtf_graphics": "RTF contains embedded pictures; all embedded pictures will be removed from the anonymized version.",
        "rtf_mapping": "Could not map RTF text back to its original formatting",
        "rtf_changes": "Invalid replacement positions in RTF",
        "pdf_dependency": "PDF requires the pypdf package: install the project dependencies",
        "pdf_scan": "PDF looks like a scan or contains only images; OCR is not enabled yet",
        "pdf_empty_pages": "PDF: {count} page(s) contain no extractable text; they may contain images",
    },
    "zh": {
        "description": "本地交互式文档匿名化工具",
        "files_help": "TXT、JSON、CSV、DOC、DOCX、RTF 或 PDF",
        "restore_help": "使用替换映射恢复文件",
        "self_test_help": "运行内置检查",
        "auto_help": "无需询问，自动替换所有检测到的值",
        "lang_help": "界面语言：ru、en 或 zh",
        "found": "发现 [{label}]：{value}",
        "context": "上下文：{value}",
        "choices": "1 - 替换   2 - 跳过   3 - 替换所有相同值   4 - 退出",
        "invalid_choice": "请输入 1、2、3 或 4。",
        "warning": "警告：{value}",
        "done": "完成：已替换 {replaced}，共检测到 {found}",
        "file": "文件：{value}",
        "mapping": "替换映射：{value} - 请与清理后的文件分开保存",
        "filename_hidden": "文件名已清理；保留安全部分：{value}",
        "restored": "已恢复：{value}",
        "empty_input": "input 文件夹为空：{value}",
        "drop_files": "请放入 TXT、JSON、CSV、DOC、DOCX、RTF 或 PDF 文件后重试。",
        "processing": "正在处理 {count} 个文件，输出到 {value}",
        "batch_errors": "处理完成但有错误；失败文件数：{count}",
        "stopped": "已停止。源文件未被修改。",
        "error": "错误：{value}",
        "error_file": "错误报告：{value}",
        "self_test": "self-test：通过",
        "encoding_error": "无法确定文件编码：{value}",
        "unsupported_format": "暂不支持格式 {value}",
        "docx_no_text": "DOCX 不包含可提取的文本",
        "doc_dependency": "DOC 需要 legacy-doc 包：请安装项目依赖",
        "doc_no_text": "DOC 不包含可提取的文本或已加密",
        "rtf_dependency": "RTF 需要 striprtf 包：请安装项目依赖",
        "rtf_no_text": "RTF 不包含可提取的文本",
        "rtf_no_highlight": "RTF 没有内联黄色高亮标记；编辑器中的高亮可能只能作为样式保留。",
        "rtf_graphics": "RTF 包含嵌入图片；匿名化版本将删除所有嵌入图片。",
        "rtf_mapping": "无法将 RTF 文本映射回原始格式",
        "rtf_changes": "RTF 中的替换位置无效",
        "pdf_dependency": "PDF 需要 pypdf 包：请安装项目依赖",
        "pdf_scan": "PDF 可能是扫描件或只包含图片；OCR 尚未启用",
        "pdf_empty_pages": "PDF：{count} 页没有可提取的文本，可能包含图片",
    },
}

ENTITY_LABELS = {
    "EMAIL": ("Email", "Email", "邮箱"),
    "PHONE": ("Телефон", "Phone", "电话"),
    "INN": ("ИНН", "Tax ID", "税号"),
    "SNILS": ("СНИЛС", "SNILS", "社保号"),
    "PASSPORT": ("Паспорт", "Passport", "护照"),
    "PERSON": ("ФИО", "Person", "姓名"),
    "ADDRESS": ("Адрес", "Address", "地址"),
    "SECRET": ("Секрет", "Secret", "密钥"),
    "CITY": ("Город", "City", "城市"),
    "COUNTRY": ("Страна", "Country", "国家"),
    "REGION": ("Регион", "Region", "地区"),
    "ORGANIZATION": ("Организация", "Organization", "组织"),
    "SENSITIVE": ("Чувствительные данные", "Sensitive data", "敏感数据"),
}


def set_language(language: str | None) -> str:
    global _language
    candidate = language or os.environ.get("VEIL_LANG", DEFAULT_LANGUAGE)
    _language = candidate if candidate in LANGUAGES else DEFAULT_LANGUAGE
    return _language


def language() -> str:
    return _language


def tr(key: str, **values: object) -> str:
    return MESSAGES[_language][key].format(**values)


def entity_label(entity_type: str) -> str:
    labels = ENTITY_LABELS.get(entity_type, ENTITY_LABELS["SENSITIVE"])
    return labels[LANGUAGES.index(_language)]
