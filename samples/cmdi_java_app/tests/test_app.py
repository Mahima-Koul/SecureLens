from pathlib import Path


def _source() -> str:
    return (Path(__file__).resolve().parents[1] / "App.java").read_text(encoding="utf-8")


def test_java_class_and_public_methods_remain_present():
    src = _source()
    assert "class App" in src
    assert "pingHostUnsafe(String host)" in src
    assert "pingLocalhostSafe()" in src
    assert "nextDisplayBannerIndex(int totalBanners)" in src


def test_ui_banner_rotation_logic_is_preserved():
    src = _source()
    assert "Math.max(1, totalBanners)" in src
