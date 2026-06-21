from src.pipeline import validation as v


def test_version_satisfies_basic():
    assert v._version_satisfies("2.10.0", ">=2.0.0") is True
    assert v._version_satisfies("1.0.0", ">=2.0.0") is False

def test_version_satisfies_with_ansi_escapes():
    # ANSI color codes shouldn't break parsing
    assert v._version_satisfies("[\x1b[34mINF\x1b[0m] Current Version: v2.9.5", ">=2.0.0") is True
    assert v._version_satisfies("nuclei version: __  __  v2.9.5", ">=2.0.0") is True
    assert v._version_satisfies("v2.10.0", ">=2.0.0") is True

def test_version_satisfies_with_logo_noise():
    # ASCII logo or junk lines
    assert v._version_satisfies("v1.5.0", ">1.0.0") is True
    assert v._version_satisfies("1.0.0", ">1.0.0") is False
