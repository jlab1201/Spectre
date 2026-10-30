"""
llm.py — platform-agnostic LLM seam for Spectre.

Spectre's two in-process model touchpoints (explain.py, direction.py) go through
this registry instead of calling one vendor directly. The provider is chosen by
``SPECTRE_LLM_PROVIDER`` (default ``host``):

    host      defer to the orchestrating agent (Claude Code, Hermes, …): return a
              prompt+schema bundle, the agent produces the JSON, and it is fed back
              through the SAME validators. No API key, fully reproducible.
    null      deterministic-only: return no output (callers surface a warning).
    deepseek  direct OpenAI-style chat/completions call (the original behavior).
    anthropic direct Anthropic Messages API call.
    openai    direct OpenAI chat/completions call.
    local     OpenAI-compatible local endpoint (ollama / llama.cpp / vLLM).

Whatever the source, output is the same parsed dict and passes the same guardrails.
Zero third-party dependencies — direct providers are thin ``urllib`` POSTs, matching
the project's existing stdlib-only style.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from spectre import config

log = logging.getLogger(__name__)


# ── Uniform response ────────────────────────────────────────────────
@dataclass
class LLMResponse:
    """One model turn. ``parsed`` is the extracted JSON object (or None)."""
    parsed: dict | None = None
    usage: dict = field(default_factory=dict)
    # OpenAI-style values: "stop", "length" (hit max_tokens; providers map
    # their own value to it), or "refusal" (safety decline — parsed is None,
    # error names the category; re-sending the same request won't help).
    finish_reason: str = ""
    raw: str = ""
    model: str = ""
    error: str | None = None
    # host mode: caller must obtain the output from the orchestrating agent.
    deferred: bool = False
    request: dict | None = None


# ── Shared JSON extraction (vendor-independent) ─────────────────────
def _extract_json(content: str, finish_reason: str) -> dict | None:
    """Pull a JSON object out of a model's text response.

    Handles ```json fences, leading prose before the first ``{``, and a
    truncated tail when the model hit the token limit.
    """
    if not content:
        return None
    content = content.strip()

    code_block = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", content, re.DOTALL)
    if code_block:
        content = code_block.group(1).strip()

    if not content.startswith("{"):
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if match:
            content = match.group(0)

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Truncated output: best-effort auto-close.
        if content.startswith("{"):
            repaired = content.rstrip().rstrip(",")
            open_braces = repaired.count("{") - repaired.count("}")
            repaired = repaired + ("}" * max(open_braces, 0))
            try:
                return json.loads(repaired)
            except json.JSONDecodeError:
                return None
        return None


def _api_key(name: str) -> str:
    """Resolve <name> from the environment, then the optional dotenv file
    (``SPECTRE_ENV_FILE`` / config.ENV_FILE)."""
    val = os.environ.get(name, "")
    if val:
        return val
    env_file = os.environ.get("SPECTRE_ENV_FILE", "") or config.ENV_FILE
    if env_file:
        try:
            from pathlib import Path
            for line in Path(env_file).expanduser().read_text().splitlines():
                line = line.strip()
                if line.startswith(f"{name}="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except OSError:
            pass
    return ""


# ── Credential redaction at the egress boundary (WS7a sub-task 4 / A3 §3b) ──
# The memory T1552.001 rule (modules/memory/rules.py's secret_env_var)
# legitimately embeds a plaintext recovered credential into a finding —
# `summary=f"vol envars: {var}={val}"` — because the finding IS the forensic
# record of that credential. That is correct: the on-disk finding must keep
# the real value. What must never happen is that plaintext leaving the local
# process boundary toward a third-party LLM provider with no redaction in
# between. The A3 review traced the live path: rules.py -> phase_runner.py's
# corroboration_note -> emit_finding.py's corroboration.artifacts[0] on disk
# -> explain._build_prompt()'s full-YAML dump / report_synthesize's
# EVIDENCE= excerpt -> provider.complete() -> _post_json()'s urlopen(). No
# redaction function existed anywhere on that path.
#
# Redacting here, inside every provider's complete(), is the single choke
# point every text egress actually passes through — direct providers' POST
# body AND the host provider's deferred `request` dict handed to whatever
# orchestrating agent is running (itself often a hosted LLM session, per
# the host-neutral provider design in this module) both originate from the same `system`/
# `user` strings passed into complete(). This is defense in depth on top of,
# not instead of, careful prompt building: it does not require every prompt
# builder (explain._build_prompt, report_synthesize._build_user_prompt, or
# any future one) to remember to call it — nothing reaches a provider's
# network call or deferred bundle without passing through this scrub first.
#
# Mirrors the memory rule's own `_SECRET_VAR` substring vocabulary
# (password|passwd|pwd|passphrase|secret|token|cred|apikey/api_key) so any
# KEY=VALUE or KEY: VALUE pair whose key NAME suggests a credential has its
# value replaced — matching the exact shape `_SECRET_VAR`-flagged env vars
# are serialized in (`{var}={val}`), plus the common `key: value` form.
# Deliberately broader than an exact-name match (over-redaction just removes
# more text from a third-party payload — the safe direction — never less;
# same philosophy documented in core/grounding.py for IOC-shaped literals).
# W2-B review (H1): every key is anchored at a key-run START (lookbehind on
# the key charset) and its prefix/suffix runs are length-bounded, so a long
# alphanumeric blob (hex/base64, no keyword) costs O(n), not O(n^2): the
# previous unanchored `[...]*{fragment}[...]*` re-scanned the run from every
# interior offset (32 KB took 27 s).
_KEY_CH = r"A-Za-z0-9_.\-"
_SECRET_KEY_FRAGMENT = (
    r"(?:pass|pwd|secret|token|cred|api[_-]?key)"
)
_KEY = (
    rf"(?<![{_KEY_CH}/])/?[{_KEY_CH}]{{0,64}}?{_SECRET_KEY_FRAGMENT}"
    rf"[{_KEY_CH}]{{0,64}}(?![{_KEY_CH}])"
)

# Whether a key NAME really names a credential is decided in Python
# (`_is_secret_key`), not in the regex, so a precise allow/deny can be
# applied. Strong fragments redact on a substring hit (DB_PASSWORD,
# AUTHTOKEN, apikey); the bare `pass` fragment only counts as a whole word
# (`pass`, `db_pass`, `--pass`, `dbPass`) so `bypass`/`compass` are left.
_STRONG_SECRET_RE = re.compile(
    r"password|passwd|passphrase|pwd|secret|token|cred|api[_-]?key", re.IGNORECASE)
_CAMEL_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

# W2-B review (M1): forensic METADATA fields whose names contain a secret
# fragment but whose values are never secrets (Windows 4624/4688/SAM/AD
# attributes). Matched on the key with separators removed, lowercased.
# Suffixes describe an attribute OF a credential (when it was set, its
# type, a counter, a flag), never the credential itself.
_BENIGN_SECRET_KEY_SUFFIXES = (
    "lastset", "type", "count", "expired", "expires", "expiry", "expiration",
    "length", "required", "notrequired", "policy", "changed", "lastchanged",
    "cantchange", "neverexpires", "doesnotexpire", "status", "flags",
    "attempt", "attempts", "maxage", "minage", "historylength",
)
_BENIGN_SECRET_KEYS = frozenset({
    "elevatedtoken",          # 4624: %%1842/%%1843 (Yes/No)
    "tokenelevation",
})
# A Windows message-table insertion string (`%%1936`) is a lookup code,
# never secret material, whatever key it hangs off.
_MSG_TABLE_REF_RE = re.compile(r"%%\d+")


def _is_secret_key(key: str) -> bool:
    k = key.strip("\"'").lstrip("-/")
    norm = re.sub(r"[^a-z0-9]", "", k.lower())
    if not norm or norm in _BENIGN_SECRET_KEYS or norm.endswith(_BENIGN_SECRET_KEY_SUFFIXES):
        return False
    if _STRONG_SECRET_RE.search(k):
        return True
    return any(w.lower() == "pass" for w in _CAMEL_WORD_RE.findall(k))


# R2-14 + W2-B review (H2): one KEY sep VALUE pass (replacing the separate
# quoted and plain passes). Value alternatives, tried in order:
#   - double-quoted with backslash escapes ("a\"b"), only when the closing
#     quote ends the value (so `abc"def` is NOT treated as quoted);
#   - single-quoted with SQL-doubled quotes ('it''s');
#   - when the KEY itself was quoted (JSON), a bare scalar up to `,`/`}`/`]`
#     /whitespace — covers `{"password": 12345}` without eating the brace;
#   - otherwise a bare run that may contain quotes, spaces and punctuation
#     ("correct horse battery", "Pa,ss;w0rd", `abc"def`) and extends to end
#     of line or stops at a genuinely separate following `key[:=]` field.
#     Over-redaction to end of line is accepted (egress-only scrub).
# The separator's surrounding blanks are [ \t]* (never a newline), so an
# empty `password:` line cannot swallow the next line.
_KV_RE = re.compile(
    rf"(?P<prefix>(?P<kq>[\"'])?(?P<key>{_KEY})(?(kq)(?P=kq))[ \t]*[:=][ \t]*)"
    r"(?P<val>"
    r"\"(?:[^\"\\\n]|\\.)*\"(?=[\s,;}\])]|$)"
    r"|'(?:[^'\n]|'')*'(?=[\s,;}\])]|$)"
    r"|(?(kq)[^\s,}\]]+"
    r"|[^\n]+?(?=[,;\s]+[\"']?[A-Za-z_][\w.\-]{0,128}[\"']?[ \t]*[:=]|[ \t]*$))"
    r")",
    re.IGNORECASE | re.MULTILINE,
)

# 3. URL userinfo: scheme://user:PASSWORD@host — credential-shaped by
#    position, no keyword needed. The password is greedy up to the LAST `@`
#    before the next `/` or whitespace, so `ftp://u:p@w0rd@host` redacts
#    `p@w0rd`, not just `p`. `(?<!\w)` keeps the scheme scan linear.
_URL_USERINFO_RE = re.compile(
    r"(?<![\w+.\-])(?P<scheme>[A-Za-z][\w+.\-]{0,31}://)(?P<user>[^/\s:@]+):(?P<pwd>[^/\s]*)@")

# 4. CLI password flags: -p/-P, space- or `=`/`:`-separated, or
#    concatenated with no separator (`-pToor123`, the psexec/mysql shape);
#    long forms --password/--passwd/--pass/-pass/-pw and schtasks `/rp`
#    require a separator (so `-passive` is not a password flag).
_CLI_PW_RE = re.compile(
    r"(?:^|(?<=\s))(?:"
    r"(?P<lflag>--?pass(?:word|wd)?|-pw|/rp)(?P<lsep>[=:]|\s+)(?P<lval>\"[^\"]*\"|\S+)"
    r"|(?P<flag>-[pP])(?P<sep>[=:]|\s+)?(?P<val>\S+)"
    r")",
    re.IGNORECASE,
)

# 5. `net user NAME PASSWORD [/add ...]` — positional, not key=value. Only
#    redact the second token when it isn't itself a `/flag`.
_NET_USER_RE = re.compile(
    r"(?P<cmd>\bnet\s+user\s+)(?P<user>\S+)\s+(?!/)(?P<pwd>\S+)",
    re.IGNORECASE,
)

# 5b. `net use [X:|*] \\\\server\\share PASSWORD [/user:...]` — positional,
#     like net user; and a PowerShell SecureString built from a literal.
_NET_USE_RE = re.compile(
    r"(?P<cmd>\bnet\s+use\s+(?:(?:[A-Za-z]:|\*)\s+)?\\\\\S+\s+)(?!/)(?P<pwd>\S+)",
    re.IGNORECASE,
)
_SECURESTRING_RE = re.compile(
    r"(?P<prefix>\bConvertTo-SecureString\s+(?:-String\s+)?)(?P<val>\"[^\"]*\"|'[^']*'|[^\s-]\S*)",
    re.IGNORECASE,
)

# 6. HTTP auth: `Authorization: Bearer|Basic|Digest|NTLM|Negotiate <cred>`
#    (header or KV form), and a standalone `Bearer <token>` of token length.
#    A bare "Basic" in prose is never touched (needs the Authorization key).
_AUTH_HEADER_RE = re.compile(
    r"(?P<prefix>\b(?:proxy-)?authorization[\"']?[ \t]*[:=][ \t]*[\"']?"
    r"(?:bearer|basic|digest|ntlm|negotiate)[ \t]+)(?P<val>[^\s\"',;]+)",
    re.IGNORECASE,
)
_BEARER_RE = re.compile(r"(?P<prefix>\b[Bb]earer[ \t]+)(?P<val>[A-Za-z0-9\-._~+/]{16,}=*)")

# 7. Well-known credential token shapes (low false-positive: fixed vendor
#    prefixes plus length/charset). AWS access key id, GitHub tokens, Slack
#    tokens, JWT (three base64url segments, first two starting `eyJ`).
_TOKEN_SHAPE_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{36,255}"
    r"|github_pat_[A-Za-z0-9_]{22,255}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,255}"
    r"|eyJ[A-Za-z0-9_-]{5,4096}\.eyJ[A-Za-z0-9_-]{5,8192}\.[A-Za-z0-9_-]{8,4096}"
    r")(?![A-Za-z0-9_])"
)

_REDACTED = "<redacted>"


def _kv_sub(m: "re.Match") -> str:
    val = m.group("val")
    if (not _is_secret_key(m.group("key"))
            or val == _REDACTED
            or _MSG_TABLE_REF_RE.fullmatch(val.strip("\"'"))):
        return m.group(0)
    if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
        return f"{m.group('prefix')}{val[0]}{_REDACTED}{val[0]}"
    return f"{m.group('prefix')}{_REDACTED}"


def _url_sub(m: "re.Match") -> str:
    return f'{m.group("scheme")}{m.group("user")}:{_REDACTED}@'


def _cli_pw_sub(m: "re.Match") -> str:
    if m.group("lflag"):
        return f'{m.group("lflag")}{m.group("lsep")}{_REDACTED}'
    sep = m.group("sep") or ""
    return f'{m.group("flag")}{sep}{_REDACTED}'


def _net_user_sub(m: "re.Match") -> str:
    return f'{m.group("cmd")}{m.group("user")} {_REDACTED}'


def _prefix_sub(m: "re.Match") -> str:
    return f'{m.group("prefix")}{_REDACTED}'


def redact_secrets(text: str) -> str:
    """Redact credential/secret-shaped values before they leave this module.

    Applied to every ``system``/``user`` prompt string right before it
    leaves this module (network POST body, or the host provider's deferred
    request bundle) — see the module-level comment above for why this is
    the chosen seam. Never touches anything on disk; the Finding YAML keeps
    the real value, only the in-memory LLM payload is scrubbed.

    Handles, in order: KEY sep VALUE (quoted/JSON/SQL-quoted/bare, multi-
    word and punctuated values; forensic metadata keys such as
    ``TokenElevationType``/``PasswordLastSet`` are left alone), URL userinfo
    (``scheme://user:pass@host``, up to the last ``@``), CLI password flags
    (``-p``/``-P``/``--password``/``--pass``/``-pass``/``-pw``/``/rp``),
    ``net user NAME PASSWORD``, ``net use \\\\share PASSWORD``,
    ``ConvertTo-SecureString "literal"``, ``Authorization:``/``Bearer`` credentials,
    and well-known token shapes (AWS key id, GitHub/Slack tokens, JWT).
    Every pattern is anchored/bounded so the scrub stays linear on long
    blobs. Over-redaction is an accepted tradeoff — this is an egress scrub,
    never the on-disk record.
    """
    if not text:
        return text
    text = _AUTH_HEADER_RE.sub(_prefix_sub, text)
    text = _KV_RE.sub(_kv_sub, text)
    text = _URL_USERINFO_RE.sub(_url_sub, text)
    text = _CLI_PW_RE.sub(_cli_pw_sub, text)
    text = _NET_USER_RE.sub(_net_user_sub, text)
    text = _NET_USE_RE.sub(lambda m: f"{m.group('cmd')}{_REDACTED}", text)
    text = _SECURESTRING_RE.sub(_prefix_sub, text)
    text = _BEARER_RE.sub(_prefix_sub, text)
    text = _TOKEN_SHAPE_RE.sub(_REDACTED, text)
    return text


def _post_json(url: str, body: dict, headers: dict) -> tuple[dict | None, str]:
    """POST JSON, return (parsed_response, error). Stdlib only."""
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=config.LLM_TIMEOUT) as resp:
            return json.loads(resp.read().decode()), ""
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.read().decode()[:300]}"
    except Exception as e:  # noqa: BLE001 — surface any transport error as a string
        return None, str(e)


# ── Providers ───────────────────────────────────────────────────────
class HostProvider:
    """Defer to the orchestrating agent. Calls no API."""
    name = "host"

    def __init__(self, provider_name="host"):
        self.mode = "host"
        # NOTE (W1-1 nit 1): this is informational provenance ONLY — under
        # host mode there is no implicit fallback to any of these, even
        # when a key is present (see complete()'s `error` message below and
        # test_pipeline/test_no_implicit_egress.py). A caller must set
        # SPECTRE_LLM_PROVIDER=<deepseek|anthropic|openai|local> explicitly
        # to actually use a direct API provider.
        self.direct_providers_available = []

        # Check for direct provider API keys (env or SPECTRE_ENV_FILE dotenv)
        if _api_key("DEEPSEEK_API_KEY"):
            self.direct_providers_available.append("deepseek")
        if _api_key("ANTHROPIC_API_KEY"):
            self.direct_providers_available.append("anthropic")
        if _api_key("OPENAI_API_KEY"):
            self.direct_providers_available.append("openai")

    def complete(self, system: str, user: str, *, max_tokens: int = 2048,
                 temperature: float = 0.0, schema=None) -> LLMResponse:
        # Redact before handing the bundle to the orchestrating agent — the
        # host isn't a network egress Spectre controls, but the data still
        # leaves the local process boundary toward whatever is orchestrating
        # (often itself a hosted LLM session; see the module comment above
        # _SECRET_KV_RE), so the same scrub applies here too.
        return LLMResponse(
            deferred=True,
            request={
                "system": redact_secrets(system),
                "user": redact_secrets(user),
                "schema": schema,
                "max_tokens": max_tokens,
                "temperature": temperature,
            },
            error=None if self.direct_providers_available else
                "Host mode: no direct LLM providers available. "
                "Set DEEPSEEK_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY.",
        )


class NullProvider:
    """Deterministic-only. Always returns no output."""
    name = "null"

    def complete(self, system: str, user: str, *, max_tokens: int = 2048,
                 temperature: float = 0.0, schema=None) -> LLMResponse:
        return LLMResponse(parsed=None)


class _OpenAIStyle:
    """Shared chat/completions provider (DeepSeek / OpenAI / local)."""
    name = ""
    _url = ""
    _key_env = ""
    _default_model = ""
    _needs_key = True

    def complete(self, system: str, user: str, *, max_tokens: int = 2048,
                 temperature: float = 0.0, schema=None) -> LLMResponse:
        model = config.LLM_MODEL or self._default_model
        headers = {}
        if self._needs_key:
            key = _api_key(self._key_env)
            if not key:
                return LLMResponse(error=f"{self._key_env} not set", model=model)
            headers["Authorization"] = f"Bearer {key}"
        # Redact credential-shaped values before they ever reach the request
        # body — this is the actual network egress point (see _SECRET_KV_RE).
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": redact_secrets(system)},
                {"role": "user", "content": redact_secrets(user)},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        data, err = _post_json(self._url, body, headers)
        if err:
            return LLMResponse(error=err, model=model)
        # A 200 can still carry an error-object body or an altered schema
        # (missing/empty/non-dict choices). Guard the extraction so the caller
        # degrades to the deterministic template instead of an unhandled
        # KeyError/IndexError/TypeError aborting the phase. The error names
        # only the body's shape, never its content.
        try:
            choice = data["choices"][0]
            content = choice["message"]["content"]
            finish = choice.get("finish_reason", "stop")
            if content is not None and not isinstance(content, str):
                raise TypeError("content is not a string")
        except (KeyError, IndexError, TypeError, AttributeError):
            shape = (sorted(data)[:10] if isinstance(data, dict)
                     else type(data).__name__)
            return LLMResponse(
                error=f"malformed 200 response body (shape: {shape})",
                model=model,
            )
        return LLMResponse(
            parsed=_extract_json(content, finish),
            usage=data.get("usage", {}),
            finish_reason=finish,
            raw=content,
            model=model,
        )


class DeepSeekProvider(_OpenAIStyle):
    name = "deepseek"
    _key_env = "DEEPSEEK_API_KEY"
    _default_model = "deepseek-v4-pro"

    @property
    def _url(self):
        return config.DEEPSEEK_API_URL


class OpenAIProvider(_OpenAIStyle):
    name = "openai"
    _key_env = "OPENAI_API_KEY"
    _default_model = "gpt-4o"

    @property
    def _url(self):
        return config.OPENAI_API_URL


class LocalProvider(_OpenAIStyle):
    name = "local"
    _needs_key = False
    _default_model = "local"

    @property
    def _url(self):
        return config.LOCAL_LLM_URL


class AnthropicProvider:
    """Direct Anthropic Messages API call."""
    name = "anthropic"
    _default_model = "claude-opus-5-5"
    # Thinking is always on for current Claude models and its tokens count
    # toward max_tokens. Callers size max_tokens for the JSON reply alone
    # (direction 512, explain/adversarial 2048-4096), so the room for thinking
    # is added here, keeping the provider-neutral call sites (and the
    # deepseek/openai/local requests they produce) unchanged.
    _THINKING_HEADROOM = 16000
    # Anthropic stop_reason -> the OpenAI-style finish_reason callers test.
    _FINISH_MAP = {"max_tokens": "length"}

    def complete(self, system: str, user: str, *, max_tokens: int = 2048,
                 temperature: float = 0.0, schema=None) -> LLMResponse:
        model = config.LLM_MODEL or self._default_model
        key = _api_key("ANTHROPIC_API_KEY")
        if not key:
            return LLMResponse(error="ANTHROPIC_API_KEY not set", model=model)
        # Request shape for current Claude models (Opus 5.5): no sampling
        # params (temperature/top_p/top_k 400), no `thinking` field (thinking
        # can't be disabled or budgeted - both 400), no assistant prefill (400).
        # Effort is the only depth/cost control, so it is always sent explicitly.
        # Redact credential-shaped values before they reach the request body
        # — this is the actual network egress point (see _SECRET_KV_RE).
        body = {
            "model": model,
            "system": redact_secrets(system),
            "messages": [{"role": "user", "content": redact_secrets(user)}],
            "max_tokens": max_tokens + self._THINKING_HEADROOM,
            "output_config": {"effort": config.LLM_EFFORT},
        }
        headers = {"x-api-key": key, "anthropic-version": "2023-06-01"}
        data, err = _post_json(config.ANTHROPIC_API_URL, body, headers)
        if err:
            return LLMResponse(error=err, model=model)
        usage = data.get("usage", {}) or {}
        usage = {
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
        }
        stop = data.get("stop_reason", "end_turn")
        if stop == "refusal":
            # A safety-classifier decline (HTTP 200). Surface it as its own
            # degraded result, not a generic "no output": re-sending the same
            # request to the same model will decline again. No server-side
            # fallback is enabled — that would change which model a finding
            # records (owner decision pending).
            details = data.get("stop_details") or {}
            category = details.get("category") or "unknown"
            served = data.get("model", model)
            log.warning("anthropic refusal: model=%s category=%s", served, category)
            return LLMResponse(
                error=f"model refusal (category: {category})",
                finish_reason="refusal",
                usage=usage,
                model=served,
            )
        blocks = data.get("content", []) or []
        content = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        finish = self._FINISH_MAP.get(stop, stop)
        return LLMResponse(
            parsed=_extract_json(content, finish),
            usage=usage,
            finish_reason=finish,
            raw=content,
            model=model,
        )


_PROVIDERS = {
    "host": HostProvider,
    "null": NullProvider,
    "deepseek": DeepSeekProvider,
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "local": LocalProvider,
}


def get_provider(name: str | None = None):
    """Return a provider instance. ``name`` overrides ``SPECTRE_LLM_PROVIDER``."""
    chosen = (name or os.environ.get("SPECTRE_LLM_PROVIDER")
              or config.LLM_PROVIDER or "host").lower()
    cls = _PROVIDERS.get(chosen)
    if cls is None:
        raise ValueError(
            f"unknown LLM provider {chosen!r}; choose from {sorted(_PROVIDERS)}"
        )
    return cls()


def preflight(provider_name: str | None = None) -> dict:
    """Cheap, no-network check of whether a provider's narrative seam will work.

    This is config liveness, not a network round-trip: it only checks env vars
    / dotenv keys and provider config, never makes an API call. Returns
    ``{"provider": str, "status": "live"|"deferred"|"dead"|"deterministic",
    "model": str, "detail": str}``.

    - ``host``: "deferred" if any direct provider key is available (the
      orchestrating agent can still act), else "dead" with a detail naming
      the env vars to set.
    - ``null``: always "deterministic" — narrative is intentionally disabled.
    - direct providers (deepseek/openai/anthropic/local): "live" if the
      provider needs no key (local) or its key is present, else "dead".
    """
    chosen = (provider_name or os.environ.get("SPECTRE_LLM_PROVIDER")
              or config.LLM_PROVIDER or "host").lower()
    provider = get_provider(chosen)

    if chosen == "null":
        return {"provider": "null", "status": "deterministic", "model": "",
                "detail": "SPECTRE_LLM_PROVIDER=null — deterministic-only, no narrative."}

    if chosen == "host":
        if provider.direct_providers_available:
            return {
                "provider": "host", "status": "deferred", "model": "",
                "detail": "Deferring to the orchestrating agent "
                          "(direct-provider keys present (not used unless "
                          "SPECTRE_LLM_PROVIDER is set explicitly): "
                          f"{provider.direct_providers_available}).",
            }
        return {
            "provider": "host", "status": "dead", "model": "",
            "detail": "No direct LLM provider keys found — set DEEPSEEK_API_KEY, "
                      "ANTHROPIC_API_KEY, or OPENAI_API_KEY, or run under a host "
                      "agent that supplies narrative output.",
        }

    # Direct providers: deepseek / openai / anthropic / local.
    model = config.LLM_MODEL or provider._default_model
    needs_key = getattr(provider, "_needs_key", True)
    if not needs_key:
        return {"provider": chosen, "status": "live", "model": model,
                "detail": f"{chosen} needs no API key."}

    key_env = getattr(provider, "_key_env", None) or f"{chosen.upper()}_API_KEY"
    if _api_key(key_env):
        return {"provider": chosen, "status": "live", "model": model,
                "detail": f"{key_env} is set."}
    return {"provider": chosen, "status": "dead", "model": model,
            "detail": f"{key_env} not set — narrative seam will be inert."}
