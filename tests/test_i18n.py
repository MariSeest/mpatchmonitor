"""Every visible string has an Italian translation and the generated files are up to date."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import i18n  # noqa: E402


def test_translations_complete_and_generated_files_current():
    assert i18n.main("check") == 0


def test_italian_units_keep_markup_safe():
    it = i18n.load_dict()
    for en, tr in it.items():
        assert "<script" not in tr.lower() and "javascript:" not in tr.lower(), en
        # placeholders must survive translation
        assert sorted(__import__("re").findall(r"\{\w+\}", en)) == sorted(__import__("re").findall(r"\{\w+\}", tr)), en
