# Veil

Локальный интерактивный анонимизатор документов перед передачей текста в LLM.

Veil работает без GUI и без локальной LLM. Он находит чувствительные данные по регулярным правилам, показывает каждое совпадение и спрашивает, заменять ли его. Исходный файл не изменяется.

## Поддерживаемые форматы

- TXT, JSON, CSV — обработка текста с сохранением расширения.
- DOCX — извлечение текста из OOXML.
- DOC — извлечение текста из старого бинарного Word через `legacy-doc`.
- RTF — преобразование в обычный текст через `striprtf`.
- PDF — извлечение текстового слоя через `pypdf`.

PPTX пока не поддерживается. OCR пока не включён: PDF, состоящий только из изображений, будет остановлен с предупреждением.

## Быстрый запуск с Python

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe anonymize.py --self-test
.\run_cmd.bat document.docx
```

Последнюю команду можно заменить на:

```powershell
.\.venv\Scripts\python.exe anonymize.py document.docx
```

Во время обработки:

```text
1 — заменить это совпадение
2 — пропустить
3 — заменить все такие значения
4 — выйти
```

## Результаты

Для `document.txt`:

```text
document.anonymized.txt
document.txt.mapping.json
```

Для DOC/DOCX/RTF/PDF результатом является очищенный текст:

```text
document.anonymized.txt
document.docx.mapping.json
```

Карта замен нужна для восстановления текста:

```powershell
python anonymize.py --restore document.anonymized.txt document.docx.mapping.json
```

Карта содержит исходные чувствительные данные. Не отправляйте её в LLM и не публикуйте в Git.

## Portable-сборка без Python на целевой машине

На машине сборки установите зависимости и выполните:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build_portable.ps1
```

Готовый portable-пакет появится в:

```text
dist\anonymizer\
```

Внутри находятся `anonymizer.exe`, `patterns.json` и `run_cmd.bat`. Пользователю не нужно устанавливать Python или добавлять что-либо в PATH.

## Правила обнаружения

Правила находятся в [patterns.json](patterns.json). Сейчас предусмотрены email, телефоны, ИНН, СНИЛС, паспортные номера, API-ключи, контекстные ФИО и адреса.

Автоматическое обнаружение не гарантирует, что найдены все чувствительные данные. Перед передачей результата в LLM проверяйте очищенный файл вручную.

## Ограничения

- Выход для офисных документов и PDF — текстовый файл, исходное оформление не сохраняется.
- OCR для сканов не используется.
- PPTX пока не поддерживается.
- Карта замен пока хранится в обычном JSON и должна защищаться пользователем.
