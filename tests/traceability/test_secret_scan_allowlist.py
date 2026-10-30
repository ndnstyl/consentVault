"""The secret scanner reads every allowlist entry, including entries that contain a "]" (a regex character class).

A "]" inside an entry once ended the list early, so every later entry was silently ignored."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _scanner():
    spec = importlib.util.spec_from_file_location("secret_scan", ROOT / "scripts" / "secret_scan.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_an_entry_with_a_bracket_does_not_cut_the_allowlist_short(tmp_path, monkeypatch):
    mod = _scanner()
    cfg = tmp_path / ".gitleaks.toml"
    cfg.write_text("[allowlist]\nregexes = [\n  '''first_[0-9a-f]+''',\n  '''second_entry''',\n]\n")
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    patterns = [p.pattern for p in mod.allowlist()]
    assert patterns == ["first_[0-9a-f]+", "second_entry"]


def test_the_repository_allowlist_loads_every_entry():
    mod = _scanner()
    text = (ROOT / ".gitleaks.toml").read_text()
    expected = text.count("'''") // 2
    assert len(mod.allowlist()) == expected
