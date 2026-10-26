from securelens.config import load_settings


def test_gemini_settings_use_gemini_environment_names(monkeypatch, tmp_path):
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test-model")
    monkeypatch.setenv("SECURELENS_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    settings = load_settings()

    assert settings.gemini_api_key == "gemini-test-key"
    assert settings.gemini_model == "gemini-test-model"
    assert settings.cache_dir == tmp_path


def test_google_api_key_is_supported_as_sdk_standard_fallback(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "google-fallback-key")

    assert load_settings().gemini_api_key == "google-fallback-key"
