from spectre import llm


def _clear_keys(monkeypatch):
    for k in ("DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("SPECTRE_ENV_FILE", "/nonexistent-env-file")


def test_null_provider_is_deterministic(monkeypatch):
    _clear_keys(monkeypatch)
    r = llm.preflight("null")
    assert r["status"] == "deterministic"
    assert r["provider"] == "null"


def test_host_without_keys_is_dead_with_actionable_detail(monkeypatch):
    _clear_keys(monkeypatch)
    r = llm.preflight("host")
    assert r["status"] == "dead"
    assert "DEEPSEEK_API_KEY" in r["detail"]


def test_host_with_key_is_deferred(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    r = llm.preflight("host")
    assert r["status"] == "deferred"


def test_host_with_key_detail_is_informational_not_fallback(monkeypatch):
    # W1-1 nit 1: this text is persisted to manifest.llm.detail. It must
    # never imply a fallback that doesn't exist under host mode -- a key
    # being present changes nothing unless SPECTRE_LLM_PROVIDER is set
    # explicitly (see test_pipeline/test_no_implicit_egress.py).
    _clear_keys(monkeypatch)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    r = llm.preflight("host")
    assert "fallback" not in r["detail"].lower()
    assert "not used unless SPECTRE_LLM_PROVIDER is set explicitly" in r["detail"]
    assert "deepseek" in r["detail"]


def test_deepseek_with_key_is_live(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    r = llm.preflight("deepseek")
    assert r["status"] == "live"
    assert r["model"]  # model name resolved


def test_deepseek_without_key_is_dead(monkeypatch):
    _clear_keys(monkeypatch)
    r = llm.preflight("deepseek")
    assert r["status"] == "dead"


def test_local_needs_no_key_is_live(monkeypatch):
    _clear_keys(monkeypatch)
    r = llm.preflight("local")
    assert r["status"] == "live"
