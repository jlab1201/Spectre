"""
test_llm.py — provider registry for the platform-agnostic LLM seam.

Covers provider selection, the host (deferred) and null (deterministic-only)
providers, direct-API request construction, and shared JSON extraction.
No network calls — direct providers are exercised by mocking urlopen.
"""
import json

import pytest

from spectre import llm


# ── Selection ──────────────────────────────────────────────────────
def test_default_provider_is_host(monkeypatch):
    monkeypatch.delenv("SPECTRE_LLM_PROVIDER", raising=False)
    assert llm.get_provider().name == "host"


def test_provider_selected_by_env(monkeypatch):
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "null")
    assert llm.get_provider().name == "null"


def test_explicit_name_overrides_env(monkeypatch):
    monkeypatch.setenv("SPECTRE_LLM_PROVIDER", "host")
    assert llm.get_provider("null").name == "null"


def test_unknown_provider_raises():
    with pytest.raises(ValueError):
        llm.get_provider("does-not-exist")


# ── null provider: deterministic-only ──────────────────────────────
def test_null_provider_returns_no_output():
    resp = llm.get_provider("null").complete("sys", "user")
    assert resp.parsed is None
    assert resp.deferred is False
    assert resp.error is None


# ── host provider: defer to the orchestrating agent ────────────────
def test_host_provider_defers_with_request_bundle():
    schema = {"type": "object"}
    resp = llm.get_provider("host").complete(
        "SYS", "USER", max_tokens=999, schema=schema
    )
    assert resp.deferred is True
    assert resp.parsed is None
    assert resp.request["system"] == "SYS"
    assert resp.request["user"] == "USER"
    assert resp.request["schema"] == schema
    assert resp.request["max_tokens"] == 999


# ── direct providers: request construction (mock urlopen) ──────────
class _FakeResp:
    def __init__(self, payload: dict):
        self._b = json.dumps(payload).encode()

    def read(self):
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _capture_urlopen(monkeypatch, payload):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode())
        return _FakeResp(payload)

    monkeypatch.setattr(llm.urllib.request, "urlopen", fake_urlopen)
    return captured


def test_deepseek_builds_openai_style_body(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k-deep")
    payload = {
        "choices": [{"message": {"content": '{"description":"ok"}'},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7},
    }
    cap = _capture_urlopen(monkeypatch, payload)
    resp = llm.get_provider("deepseek").complete("sys", "user")
    assert resp.parsed == {"description": "ok"}
    assert resp.usage["prompt_tokens"] == 5
    assert cap["body"]["messages"][0]["role"] == "system"
    assert cap["body"]["temperature"] == 0.0
    assert "deepseek" in cap["url"]


def test_anthropic_builds_messages_body(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    payload = {
        "content": [{"type": "text", "text": '{"description":"ok"}'}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 3, "output_tokens": 4},
    }
    cap = _capture_urlopen(monkeypatch, payload)
    resp = llm.get_provider("anthropic").complete("sys", "user")
    assert resp.parsed == {"description": "ok"}
    # Anthropic carries system top-level, not as a message role
    assert cap["body"]["system"] == "sys"
    assert cap["body"]["messages"][0]["role"] == "user"
    assert "x-api-key" in {k.lower() for k in cap["headers"]}


def test_anthropic_omits_sampling_params(monkeypatch):
    """Current Claude models 400 on temperature/top_p/top_k — never send them."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    payload = {
        "content": [{"type": "text", "text": '{"description":"ok"}'}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 3, "output_tokens": 4},
    }
    cap = _capture_urlopen(monkeypatch, payload)
    llm.get_provider("anthropic").complete("sys", "user", temperature=0.0)
    assert "temperature" not in cap["body"]
    assert "top_p" not in cap["body"]


_OK_ANTHROPIC = {
    "content": [{"type": "text", "text": '{"description":"ok"}'}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 3, "output_tokens": 4},
}


def test_anthropic_default_model_is_opus_5_5(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    monkeypatch.setattr(llm.config, "LLM_MODEL", "")
    cap = _capture_urlopen(monkeypatch, _OK_ANTHROPIC)
    llm.get_provider("anthropic").complete("sys", "user")
    assert cap["body"]["model"] == "claude-opus-5-5"


def test_anthropic_never_sends_thinking_sampling_or_prefill(monkeypatch):
    """Opus 5.5: thinking can't be disabled/budgeted, sampling params 400,
    and an assistant prefill 400s — none of them may appear in the body."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    cap = _capture_urlopen(monkeypatch, _OK_ANTHROPIC)
    llm.get_provider("anthropic").complete("sys", "user", temperature=0.7)
    body = cap["body"]
    for k in ("thinking", "temperature", "top_p", "top_k", "budget_tokens"):
        assert k not in body
    assert [m["role"] for m in body["messages"]] == ["user"]


def test_anthropic_sets_effort_explicitly(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    monkeypatch.setattr(llm.config, "LLM_EFFORT", "high")
    cap = _capture_urlopen(monkeypatch, _OK_ANTHROPIC)
    llm.get_provider("anthropic").complete("sys", "user")
    assert cap["body"]["output_config"] == {"effort": "high"}


def test_effort_default_and_env_override(monkeypatch):
    import importlib
    from spectre import config
    monkeypatch.delenv("SPECTRE_LLM_EFFORT", raising=False)
    assert importlib.reload(config).LLM_EFFORT == "medium"
    monkeypatch.setenv("SPECTRE_LLM_EFFORT", "xhigh")
    assert importlib.reload(config).LLM_EFFORT == "xhigh"
    monkeypatch.delenv("SPECTRE_LLM_EFFORT")
    importlib.reload(config)


def test_anthropic_adds_thinking_headroom_to_small_budgets(monkeypatch):
    """Thinking counts toward max_tokens; direction's 512 must not be eaten."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    cap = _capture_urlopen(monkeypatch, _OK_ANTHROPIC)
    p = llm.get_provider("anthropic")
    p.complete("sys", "user", max_tokens=512)
    assert cap["body"]["max_tokens"] == 512 + p._THINKING_HEADROOM
    assert p._THINKING_HEADROOM >= 8000


def test_openai_style_max_tokens_unchanged(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k-deep")
    payload = {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}]}
    cap = _capture_urlopen(monkeypatch, payload)
    llm.get_provider("deepseek").complete("sys", "user", max_tokens=512)
    assert cap["body"]["max_tokens"] == 512
    assert "output_config" not in cap["body"]


def test_anthropic_max_tokens_stop_normalized_to_length(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    payload = dict(_OK_ANTHROPIC, stop_reason="max_tokens")
    _capture_urlopen(monkeypatch, payload)
    resp = llm.get_provider("anthropic").complete("sys", "user")
    assert resp.finish_reason == "length"


def test_anthropic_refusal_is_distinct_and_logged(monkeypatch, caplog):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    payload = {
        "content": [],
        "stop_reason": "refusal",
        "stop_details": {"type": "refusal", "category": "cyber",
                         "explanation": "x"},
        "usage": {"input_tokens": 3, "output_tokens": 0},
        "model": "claude-opus-5-5",
    }
    _capture_urlopen(monkeypatch, payload)
    with caplog.at_level("WARNING", logger="spectre.llm"):
        resp = llm.get_provider("anthropic").complete("sys", "user")
    assert resp.parsed is None
    assert resp.finish_reason == "refusal"
    assert "refus" in resp.error and "cyber" in resp.error
    assert resp.usage["prompt_tokens"] == 3
    assert any("refus" in r.getMessage() for r in caplog.records)


def test_anthropic_refusal_without_category(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-anthropic")
    payload = {"content": [], "stop_reason": "refusal", "stop_details": None}
    _capture_urlopen(monkeypatch, payload)
    resp = llm.get_provider("anthropic").complete("sys", "user")
    assert resp.finish_reason == "refusal"
    assert "unknown" in resp.error


def test_api_key_falls_back_to_env_file(monkeypatch, tmp_path):
    """SPECTRE_ENV_FILE dotenv is consulted when the env var is unset."""
    env_file = tmp_path / ".env"
    env_file.write_text("# keys\nDEEPSEEK_API_KEY=from-file\nOTHER=x\n")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("SPECTRE_ENV_FILE", str(env_file))
    assert llm._api_key("DEEPSEEK_API_KEY") == "from-file"


def test_api_key_env_var_wins_over_env_file(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("DEEPSEEK_API_KEY=from-file\n")
    monkeypatch.setenv("DEEPSEEK_API_KEY", "from-env")
    monkeypatch.setenv("SPECTRE_ENV_FILE", str(env_file))
    assert llm._api_key("DEEPSEEK_API_KEY") == "from-env"


def test_openai_style_200_error_body_returns_error(monkeypatch):
    """TB-port T2: a 200 response whose body is an error object (no
    'choices') must degrade to LLMResponse(error=...), never raise
    KeyError/IndexError out of the provider (which would abort the phase)."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k-deep")
    _capture_urlopen(monkeypatch, {"error": {"message": "overloaded",
                                             "type": "server_error"}})
    resp = llm.get_provider("deepseek").complete("sys", "user")
    assert resp.parsed is None
    assert resp.error


@pytest.mark.parametrize("payload", [
    {"choices": []},
    {"choices": None},
    {"choices": ["not-a-dict"]},
    {"choices": [{"message": None}]},
    {"choices": [{"no_message": 1}]},
    ["a", "list", "body"],
])
def test_openai_style_200_malformed_choices_returns_error(monkeypatch, payload):
    """Every malformed-choices shape degrades to an error response."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k-deep")
    _capture_urlopen(monkeypatch, payload)
    resp = llm.get_provider("deepseek").complete("sys", "user")
    assert resp.parsed is None
    assert resp.error
    assert "malformed" in resp.error


def test_direct_provider_without_key_errors(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("SPECTRE_ENV_FILE", "/nonexistent/path/.env")
    resp = llm.get_provider("deepseek").complete("sys", "user")
    assert resp.parsed is None
    assert resp.error


# ── W1-1: first_direct_provider() (the host-mode implicit-fallback
# discovery helper) was removed entirely along with its two call sites in
# direction.py and phase_runner.py — see test_direction.py and
# test_pipeline/test_no_implicit_egress.py for the no-egress guarantees
# that replaced it. `llm.first_direct_provider` no longer exists.
def test_first_direct_provider_removed():
    assert not hasattr(llm, "first_direct_provider"), (
        "first_direct_provider() was the implicit host->API fallback "
        "discovery helper (R2-06/W1-1) and must stay removed, not be "
        "silently reintroduced as a new call site's convenience import"
    )


# ── WS7a sub-task 4 (A3 §3b): credential redaction at LLM egress ──────
# The memory T1552.001 rule embeds a PLAINTEXT recovered credential into a
# finding (summary=f"vol envars: {var}={val}") — that is correct forensic
# recordkeeping and must stay on disk. What must never happen is that
# plaintext reaching a third-party LLM provider unredacted. These tests
# pin the redaction seam directly in llm.py, the last stop before any
# provider call or deferred host bundle.

def test_redact_secrets_simple_kv():
    assert llm.redact_secrets("PASSWORD=hunter2") == "PASSWORD=<redacted>"


def test_redact_secrets_env_var_shaped_like_memory_rule_output():
    # Exact shape secret_env_var() emits: "vol envars: {var}={val}"
    text = "EVIDENCE=vol envars: DB_PASSWORD=hunter2"
    redacted = llm.redact_secrets(text)
    assert "hunter2" not in redacted
    assert "DB_PASSWORD=<redacted>" in redacted


def test_redact_secrets_colon_form():
    assert "hunter2" not in llm.redact_secrets("password: hunter2")


def test_redact_secrets_api_key_and_token_variants():
    for text in ("API_KEY=sk-abc123", "api-key=sk-abc123",
                 "AUTH_TOKEN=eyJhbGciOiJIUzI1NiJ9", "AWS_SECRET_ACCESS_KEY=AKIAFAKEVALUE"):
        redacted = llm.redact_secrets(text)
        assert "<redacted>" in redacted
        # The literal secret value must not survive.
        value = text.split("=", 1)[1]
        assert value not in redacted


def test_redact_secrets_leaves_ordinary_text_untouched():
    text = "The host contacted 45.131.214.85 over HTTP on port 443."
    assert llm.redact_secrets(text) == text


def test_redact_secrets_empty_and_none_safe():
    assert llm.redact_secrets("") == ""


# ── R2-14: redact_secrets missed shapes (quoted/JSON/multi-word/CLI) ──
# WS7a's original single substring-value regex only consumed one
# whitespace-free token after KEY=, so it missed everything below. Each
# case names the value that must never survive redaction.
_R2_14_CASES = [
    ("multi-word value", 'PASSWORD=correct horse battery', "correct horse battery"),
    ("punctuated value", 'PASSWORD=Pa,ss;w0rd', "Pa,ss;w0rd"),
    ("quoted value, spaced =", 'PASSWORD = "quoted value"', "quoted value"),
    ("quoted value, single quotes", "PASSWORD='quoted value'", "quoted value"),
    ("JSON key/value", '{"DB_PASSWORD": "hunter2"}', "hunter2"),
    ("psexec -p", "psexec -p Winter2024!", "Winter2024!"),
    ("mysql -p concatenated", "mysql -pToor123", "Toor123"),
    ("net user positional", "net user admin S3cr3t! /add", "S3cr3t!"),
    ("URL userinfo", "https://svc:Winter2024!@host/path", "Winter2024!"),
    ("--password long flag", "tool --password=Winter2024!", "Winter2024!"),
]


@pytest.mark.parametrize("label,text,secret", _R2_14_CASES, ids=[c[0] for c in _R2_14_CASES])
def test_redact_secrets_r2_14_shapes(label, text, secret):
    redacted = llm.redact_secrets(text)
    assert secret not in redacted, f"{label}: secret value leaked in {redacted!r}"


def test_redact_secrets_net_user_no_password_untouched():
    # No password token present (just a flag) — nothing to redact, and the
    # flag itself must survive.
    text = "net user admin /add"
    assert llm.redact_secrets(text) == text


def test_redact_secrets_json_key_stays_readable():
    redacted = llm.redact_secrets('{"DB_PASSWORD": "hunter2"}')
    assert "hunter2" not in redacted
    assert '"DB_PASSWORD"' in redacted
    assert "<redacted>" in redacted


def test_redact_secrets_cli_password_does_not_eat_unrelated_flag():
    # A plain, unrelated CLI token must not be mistaken for a -p/-P flag.
    text = "tool --port 8080 --verbose"
    assert "8080" in llm.redact_secrets(text)


def test_host_provider_redacts_deferred_request_bundle():
    resp = llm.get_provider("host").complete(
        "SYS", "Finding EVIDENCE=vol envars: PASSWORD=hunter2 recorded."
    )
    assert "hunter2" not in resp.request["user"]
    assert "PASSWORD=<redacted>" in resp.request["user"]


def test_direct_provider_egress_redacts_credential(monkeypatch):
    # End-to-end at the real network-egress seam: the POST body must never
    # carry the plaintext credential value, even though the caller passed
    # it in untouched (mirroring explain._build_prompt not redacting).
    monkeypatch.setenv("DEEPSEEK_API_KEY", "k-deep")
    payload = {
        "choices": [{"message": {"content": '{"description":"ok"}'},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    cap = _capture_urlopen(monkeypatch, payload)
    llm.get_provider("deepseek").complete(
        "sys", "Finding EVIDENCE=vol envars: PASSWORD=hunter2 recorded."
    )
    body_str = json.dumps(cap["body"])
    assert "hunter2" not in body_str
    assert "PASSWORD=<redacted>" in body_str


# ── shared JSON extraction ─────────────────────────────────────────
def test_extract_json_from_code_block():
    out = llm._extract_json('```json\n{"a": 1}\n```', "stop")
    assert out == {"a": 1}


def test_extract_json_repairs_truncation():
    out = llm._extract_json('{"a": "b", "c": "d"', "length")
    assert out["a"] == "b"


# ── W2-B review fixes: redact_secrets perf, leaks, over-redaction ─────
import time  # noqa: E402


@pytest.mark.parametrize("blob", [
    "A" * 65536,
    ("QUJDRGVmZ2hpams0NTY3ODkw" * 3000)[:65536],
    "0123456789abcdef" * 4096,
])
def test_redact_secrets_is_linear_on_long_alnum_runs(blob):
    # H1: an unanchored key prefix made this O(n^2) (32 KB took 27 s).
    t0 = time.perf_counter()
    assert llm.redact_secrets(blob) == blob
    assert time.perf_counter() - t0 < 0.5


def test_redact_secrets_long_run_ending_in_keyword_is_fast():
    blob = "x" * 65536 + "password=hunter2"
    t0 = time.perf_counter()
    llm.redact_secrets(blob)
    assert time.perf_counter() - t0 < 0.5


_W2B_LEAK_CASES = [
    ("json number", '{"password": 12345}', "12345"),
    ("json bare true-ish", '{"api_key": sk_live_abcdef}', "sk_live_abcdef"),
    ("embedded quote", 'client_secret=abc"def', 'abc"def'),
    ("embedded quote tail", 'client_secret=abc"def', "def"),
    ("sql doubled quote", "PASSWORD='it''s'", "s'"),
    ("url userinfo with @", "ftp://u:p@w0rd@host/x", "w0rd"),
    ("-pass flag", "openssl enc -pass abc123", "abc123"),
    ("--pass= flag", "tool --pass=abc123", "abc123"),
    ("schtasks /rp", "schtasks /create /ru admin /rp Secret1 /tn x", "Secret1"),
    ("pass= kv", "user=x pass=abc123", "abc123"),
    ("wmic /password:", "wmic /node:h /user:a /password:abc123 process", "abc123"),
    ("net use positional", r"net use Z: \\srv\share Pass123 /user:bob", "Pass123"),
    ("SecureString literal", 'ConvertTo-SecureString "Pa55w0rd" -AsPlainText -Force', "Pa55w0rd"),
    ("bearer header", "Authorization: Bearer abcdef0123456789xyz", "abcdef0123456789xyz"),
    ("basic header", "Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
    ("aws key id", "found AKIAIOSFODNN7EXAMPLE in env", "AKIAIOSFODNN7EXAMPLE"),
    ("github pat", "ghp_" + "a1B2" * 9 + " leaked", "a1B2" * 9),
    ("jwt", "cookie eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U x",
     "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
]


@pytest.mark.parametrize("label,text,secret", _W2B_LEAK_CASES,
                         ids=[c[0] for c in _W2B_LEAK_CASES])
def test_redact_secrets_w2b_leak_shapes(label, text, secret):
    redacted = llm.redact_secrets(text)
    assert secret not in redacted, f"{label}: leaked in {redacted!r}"


@pytest.mark.parametrize("text", [
    "TokenElevationType=%%1938",
    "PasswordLastSet=2020-01-01T00:00:00Z",
    "TokenElevationType: %%1936",
    "BadPasswordCount=3",
    "PasswordExpired=False",
    "ElevatedToken=%%1842",
    "bypass=true",
    "Authorization is Basic in this doc",
    "The token was checked.",
])
def test_redact_secrets_leaves_forensic_metadata_fields(text):
    assert llm.redact_secrets(text) == text


def test_redact_secrets_metadata_field_does_not_shield_following_secret():
    out = llm.redact_secrets("PasswordLastSet=2020 password=hunter2")
    assert "PasswordLastSet=2020" in out
    assert "hunter2" not in out


def test_redact_secrets_json_number_keeps_structure():
    assert llm.redact_secrets('{"password": 12345}') == '{"password": <redacted>}'


def test_redact_secrets_url_host_survives():
    out = llm.redact_secrets("ftp://u:p@w0rd@host.example/x")
    assert out == "ftp://u:<redacted>@host.example/x"
