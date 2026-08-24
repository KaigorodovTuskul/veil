# Changelog

## 0.2.0

- Made regex matching case-insensitive for uppercase documents.
- Added normalization for invisible spaces and dash variants.
- Added organization suffix detection for joined and spaced names such as `Пупкинбанк` and `Пуп кинбанк`.
- Removed broad city-by-preposition matching and added context stop words to reduce false positives.
- Fixed RTF replacement offsets and batch processing so one broken file does not stop the remaining files.
- Documented launcher arguments in `run_cmd.bat`.
- Added `--auto` mode for unattended replacement.
- Added Russian, English, and Simplified Chinese UI via `--lang` or `VEIL_LANG`.
- Output filenames now preserve safe source parts and remove detected sensitive fragments; removed values remain only in private mappings.
- Expanded detection for names, initials, inflected names, cities, regions, countries, organizations, addresses, and email punctuation.
- Preserved RTF structure while replacing text.
- Fixed RTF Unicode fallback characters that could remain after a replacement.
- Added detection for initials-before-surname patterns and foreign company names after explicit company context.
- Added country detection inside ordinary sentences, including inflected forms such as `России`.
- Removed embedded RTF pictures and drawing objects from anonymized output.
- Added portable Windows build documentation and CI configuration.
