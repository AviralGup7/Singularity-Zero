import json
from pathlib import Path

_CURRENT_LANGUAGE = "en"
_TRANSLATIONS: dict[str, dict[str, str]] = {}

# Locate locales directory relative to this file
LOCALES_DIR = Path(__file__).parent / "locales"


def set_language(lang: str) -> None:
    global _CURRENT_LANGUAGE
    _CURRENT_LANGUAGE = lang.strip().lower()


def get_language() -> str:
    return _CURRENT_LANGUAGE


def load_translations(lang: str, catalog: dict[str, str]) -> None:
    _TRANSLATIONS.setdefault(lang.strip().lower(), {}).update(catalog)


def load_locale_files() -> None:
    if LOCALES_DIR.exists():
        for f in LOCALES_DIR.glob("*.json"):
            try:
                lang = f.stem.lower()
                with open(f, encoding="utf-8") as fd:
                    catalog = json.load(fd)
                    if isinstance(catalog, dict):
                        load_translations(lang, catalog)
            except Exception:
                pass


def t(text: str) -> str:
    lang = get_language()
    if lang == "en":
        return text
    # Try translation lookup
    translated = _TRANSLATIONS.get(lang, {}).get(text)
    if translated is not None:
        return translated
    return text


# Auto-initialize
load_locale_files()
