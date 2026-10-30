"""
config.py — Centralized configuration for Spectre forensic pipeline.

Every path in the project resolves through this module. Override via
environment variables or edit defaults for your system.

Environment variables:
    SPECTRE_CASES_DIR    — where case directories live (default: ~/spectre-cases/)
    SPECTRE_CACHE_DIR    — volatility3 symbols and other caches
    SPECTRE_VOL_PATH     — path to 'vol' binary (default: discovers via PATH)
    SPECTRE_MMLS_PATH    — path to mmls
    SPECTRE_FLS_PATH     — path to fls
    SPECTRE_ICAT_PATH    — path to icat
    SPECTRE_LOG2TIMELINE — path to log2timeline.py (default: PATH)
    SPECTRE_PSORT        — path to psort.py (default: PATH)
    SPECTRE_MEMPROCFS_DIR — path to MemProcFS installation (default: /opt/memprocfs)
    SPECTRE_MEMPROCFS_TIMEOUT — seconds before the MemProcFS extraction
                           subprocess is torn down (default: 600)
    SPECTRE_MEMORY_ENGINE — memory extraction engine: vol | memprocfs | both
                           (default: both — dual-engine, so claims corroborate)
    SPECTRE_ZEEK_PATH    — path to 'zeek' binary (default: PATH, then /opt/zeek/bin)
    SPECTRE_ZEEK_POLICY  — optional extra Zeek policy script to load per run
    SPECTRE_PCAP_ENGINE  — pcap extraction engine: auto | zeek | manual
                           (default: auto — Zeek when available, else tcpdump/tshark)

Timeouts (seconds) and limits:
    SPECTRE_TOOL_TIMEOUT   — default per external-tool timeout (default: 300)
    SPECTRE_PLASO_TIMEOUT  — log2timeline/psort timeout (default: 1800)
    SPECTRE_CANARY_TIMEOUT — canary environment-probe timeout (default: 120)
    SPECTRE_NORMALIZE_BATCH_SIZE — logfile streaming batch size in rows
                           (default: 10000)
    SPECTRE_LOGFILE_MAX_EVENTS — cap on events one line-oriented logfile may
                           emit; the remainder is reported as un-analyzed
                           (default: 200000; 0 = no cap)
    SPECTRE_TEMPORAL_WINDOW_S — cross-artifact clustering temporal window
                           (default: 60; read in
                           pipeline/correlation/clustering.py, not config.py)

Audit-chain external anchors (WS1c — see spectre.pipeline.audit; defends the
A1-H2 same-OS-user "re-derive the chain forward" attacker and the A1-H3
case-handoff attacker; neither is sold as tamper-proof against an attacker
who fully controls the machine AND possesses any configured key):
    SPECTRE_AUDIT_JOURNAL_ANCHOR — best-effort external checkpoint of the
                           audit chain tail into the systemd journal (a
                           non-root user can append but not rewrite prior
                           journal entries). "0"/"false"/"no"/"off" disables
                           it; default on, and always graceful — hosts with
                           no systemd/journald/logger (CI, containers,
                           macOS) silently no-op.
    SPECTRE_AUDIT_HMAC_KEY — opt-in literal secret: when set, audit.py
                           computes an HMAC-SHA256 over each row's
                           entry_sha256 and stores it on the row. Off by
                           default (unset -> byte-identical behavior to
                           before this existed). Never set from inside, or
                           written into, the case directory.
    SPECTRE_AUDIT_HMAC_KEYFILE — path to a file holding the same key,
                           used when SPECTRE_AUDIT_HMAC_KEY is unset.

LLM (platform-agnostic explain/direction seam — see spectre.llm):
    SPECTRE_LLM_PROVIDER — host | null | deepseek | anthropic | openai | local
                           (default: host — defer to the orchestrating agent)
    SPECTRE_LLM_MODEL    — override the provider's default model
    SPECTRE_ENV_FILE     — optional dotenv file to source API keys from
                           (unset: ~/.spectre.env if it exists)
    SPECTRE_LLM_TIMEOUT  — per-call API timeout (default: 300)
    SPECTRE_LLM_MAX_TOKENS_SYNTH — output-token ceiling for Phase 6 report
                           synthesis (default: 16384)
    SPECTRE_LLM_EFFORT   — anthropic provider only: output_config.effort
                           (low|medium|high|xhigh|max; default: medium)
    SPECTRE_DEEPSEEK_URL / SPECTRE_ANTHROPIC_URL / SPECTRE_OPENAI_URL —
                           override a direct provider's endpoint (proxy/self-host)
    SPECTRE_LOCAL_LLM_URL — full chat-completions URL of an OpenAI-compatible
                           local endpoint (default: http://localhost:11434/v1/chat/completions)
    <PROVIDER>_API_KEY   — DEEPSEEK_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY
"""
import os
import shutil
from pathlib import Path

# ── Package root discovery ────────────────────────────────────────
# Works whether installed via pip or running from repo.
_PACKAGE_ROOT = Path(__file__).parent.resolve()          # src/spectre/
_PROJECT_ROOT = _PACKAGE_ROOT.parent.parent              # repo root

# ── Directories ────────────────────────────────────────────────────
CASES_DIR = Path(os.environ.get(
    "SPECTRE_CASES_DIR",
    str(Path.home() / "spectre-cases"),
))

CACHE_DIR = Path(os.environ.get(
    "SPECTRE_CACHE_DIR",
    str(Path.home() / ".cache" / "spectre"),
))

# Raw tool-extraction subdir of a case dir (was "output"). One literal, here.
RAW_DIR = "raw_extract"

KNOWLEDGE_DIR = _PACKAGE_ROOT / "knowledge" / "artifacts"
MITRE_MAP_PATH = _PACKAGE_ROOT / "knowledge" / "mitre-map.yaml"
# Flat tid -> canonical ATT&CK technique-name map. Source of truth for
# PER-TECHNIQUE report labels — never a mitre-map.yaml rule's composite label.
MITRE_TECHNIQUES_PATH = _PACKAGE_ROOT / "knowledge" / "mitre_techniques.yaml"
# CANARY_SCRIPT / REGISTER_SCRIPT removed. Both resolved into <repo>/scripts/,
# which hatchling does not put in the wheel (packages = ["src/spectre"]), so
# both were broken on any non-editable install — and neither had a consumer.
# The canary is now pure Python derived from the module manifests
# (pipeline/canary.py); evidence registration goes through
# pipeline/evidence_guard.py. _PROJECT_ROOT stays below for _PACKAGE_ROOT's
# sake, but nothing may resolve runtime dependencies through it again: a path
# that only exists in a source checkout is a path that fails in the field.

# Knowledge subdirs
FK_WINDOWS_DIR = KNOWLEDGE_DIR / "windows"
FK_NETWORK_DIR = KNOWLEDGE_DIR / "network"
FK_LOGS_DIR = KNOWLEDGE_DIR / "logs"
FK_DISK_DIR = KNOWLEDGE_DIR / "disk"
FK_DIRS = [FK_WINDOWS_DIR, FK_NETWORK_DIR, FK_LOGS_DIR, FK_DISK_DIR]

# Shared indicator lists (executables, hosts, ports, path markers) used by
# rule packs. Separate from FK YAML (which carries per-artifact caveats).
INDICATORS_DIR = _PACKAGE_ROOT / "knowledge" / "indicators"
PLAYBOOKS_DIR = _PACKAGE_ROOT / "knowledge" / "playbooks"

# ── Large-file partitioning (logfile module) ──────────────────────
# Batch size for memory-bounded streaming reads of CSV / unix .log evidence.
NORMALIZE_BATCH_SIZE = int(os.environ.get("SPECTRE_NORMALIZE_BATCH_SIZE", "10000"))
# Cap on events a single line-oriented file may emit. Protects downstream
# (Phase 2/3 still materialize events). When exceeded, the remainder is
# reported as un-analyzed (surfaced, never silently dropped). 0 = no cap.
LOGFILE_MAX_EVENTS = int(os.environ.get("SPECTRE_LOGFILE_MAX_EVENTS", "200000"))

# ── Tool paths (discoverable, overridable) ────────────────────────
def _which_or(name: str, env_var: str, fallback: str) -> str:
    """Return env var if set, else discover via PATH, else fallback."""
    val = os.environ.get(env_var)
    if val:
        return val
    found = shutil.which(name)
    if found:
        return found
    return fallback

VOL_PATH = _which_or("vol", "SPECTRE_VOL_PATH", "vol")
# EVTX_DUMP / YARA_PATH removed: zero consumers. evtx extraction runs the
# `evtxexport` binary its module declares (modules/evtx/extract.py); nothing
# ever shelled out to yara. A resolved path to a tool no module declares is an
# invitation to add an unaudited tool call.
MMLS_PATH = _which_or("mmls", "SPECTRE_MMLS_PATH", "mmls")
FLS_PATH = _which_or("fls", "SPECTRE_FLS_PATH", "fls")
ICAT_PATH = _which_or("icat", "SPECTRE_ICAT_PATH", "icat")
LOG2TIMELINE = _which_or("log2timeline.py", "SPECTRE_LOG2TIMELINE", "log2timeline.py")
PSORT = _which_or("psort.py", "SPECTRE_PSORT", "psort.py")

# MemProcFS — not on PATH, has a known install location
MEMPROCFS_DIR = os.environ.get("SPECTRE_MEMPROCFS_DIR", "/opt/memprocfs")
MEMPROCFS_BIN = os.path.join(MEMPROCFS_DIR, "memprocfs")
# Ceiling on the whole MemProcFS pass (mount + read every artifact). The old
# hardcoded 300 s was inconsistent with volatility's 900 s *per plugin* across
# 13 plugins; a 1.5 GB dump mounts and reads in ~90 s here, so 600 s is real
# headroom without letting a wedged FUSE mount hold the pipeline indefinitely.
MEMPROCFS_TIMEOUT = int(os.environ.get("SPECTRE_MEMPROCFS_TIMEOUT", "600"))
# Engine selector for memory extraction: vol | memprocfs | both. Empty means
# unset, which `modules.memory.extract` reads as "both" — two engines over one
# image is what lets matching claims corroborate. An explicit argument (the
# `spectre-memory --engine` flag) overrides this.
MEMORY_ENGINE = os.environ.get("SPECTRE_MEMORY_ENGINE", "").strip().lower()


def _resolve_zeek() -> str:
    """Resolve the zeek binary: env override, then PATH, then well-known
    install prefixes (Zeek's default is /opt/zeek, and it is usually NOT on
    PATH). Falls back to the bare name so a missing Zeek surfaces as a
    graceful 'not found' at extract time (→ manual fallback), never a crash."""
    env = os.environ.get("SPECTRE_ZEEK_PATH")
    if env:
        return env
    found = shutil.which("zeek")
    if found:
        return found
    for cand in ("/opt/zeek/bin/zeek", "/usr/local/zeek/bin/zeek"):
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return "zeek"


ZEEK_PATH = _resolve_zeek()
# Optional extra policy script layered on top of the bundled spectre.zeek.
ZEEK_POLICY = os.environ.get("SPECTRE_ZEEK_POLICY", "")
# Engine selector for pcap extraction. "auto" uses Zeek when its binary
# resolves, else the tcpdump/tshark passes; "zeek" forces Zeek (still runs
# the manual gap-filling passes it can't cheaply replace); "manual" forces
# the legacy tcpdump/tshark-only path.
PCAP_ENGINE = os.environ.get("SPECTRE_PCAP_ENGINE", "auto").strip().lower()

# ── Volatility3 symbols cache ──────────────────────────────────────
VOL_SYMBOLS_DIR = CACHE_DIR / "volatility3" / "symbols"

# ── Knowledge base index ───────────────────────────────────────────
INDEX_DB = CACHE_DIR / "index.db"

# ── Timeouts (seconds) ─────────────────────────────────────────────
TOOL_TIMEOUT = int(os.environ.get("SPECTRE_TOOL_TIMEOUT", "300"))
PLASO_TIMEOUT = int(os.environ.get("SPECTRE_PLASO_TIMEOUT", "1800"))
CANARY_TIMEOUT = int(os.environ.get("SPECTRE_CANARY_TIMEOUT", "120"))

# ── LLM seam (platform-agnostic; see spectre.llm) ──────────────────
# Default "host": Spectre calls no API itself — it hands the prompt to the
# orchestrating agent (Claude Code, Hermes, …), which produces the output and
# feeds it back through the same validators. This keeps zero-key reproducibility
# and makes Hermes/DeepSeek just one backend among several.
LLM_PROVIDER = os.environ.get("SPECTRE_LLM_PROVIDER", "host")
LLM_MODEL = os.environ.get("SPECTRE_LLM_MODEL", "")  # "" -> provider default
# 60s starved Phase 6 synthesis (a 21-finding narrative generates for ~2min).
LLM_TIMEOUT = int(os.environ.get("SPECTRE_LLM_TIMEOUT", "300"))
# Output ceiling for Phase 6 report synthesis (long narrative + verdict).
# 21 findings needed ~7.5K completion tokens; 8192 truncated mid-JSON.
LLM_MAX_TOKENS_SYNTH = int(os.environ.get("SPECTRE_LLM_MAX_TOKENS_SYNTH", "16384"))
# Anthropic provider only. Current Claude models (Opus 5.5) always think and
# effort is the only depth/cost/latency control; Opus 5.5's own default is
# medium, pinned here explicitly so a model change can't silently move it.
# medium also keeps non-streaming calls inside LLM_TIMEOUT.
LLM_EFFORT = os.environ.get("SPECTRE_LLM_EFFORT", "medium").strip().lower()

# Optional dotenv file for API keys. When SPECTRE_ENV_FILE is unset, fall back
# to ~/.spectre.env if it exists, so a standalone `spectre` run discovers
# direct-provider keys (DEEPSEEK_API_KEY, …) without exporting env vars. Keep
# that file chmod 600 — it holds secrets.
_DEFAULT_ENV_FILE = Path.home() / ".spectre.env"
ENV_FILE = os.environ.get("SPECTRE_ENV_FILE", "") or (
    str(_DEFAULT_ENV_FILE) if _DEFAULT_ENV_FILE.exists() else "")

# Direct-provider endpoints (overridable for proxies / self-hosting).
DEEPSEEK_API_URL = os.environ.get(
    "SPECTRE_DEEPSEEK_URL", "https://api.deepseek.com/v1/chat/completions")
ANTHROPIC_API_URL = os.environ.get(
    "SPECTRE_ANTHROPIC_URL", "https://api.anthropic.com/v1/messages")
OPENAI_API_URL = os.environ.get(
    "SPECTRE_OPENAI_URL", "https://api.openai.com/v1/chat/completions")
# OpenAI-compatible local endpoint (ollama / llama.cpp / vLLM).
LOCAL_LLM_URL = os.environ.get(
    "SPECTRE_LOCAL_LLM_URL", "http://localhost:11434/v1/chat/completions")

# ── Audit-chain external anchors (WS1c) ────────────────────────────
# Both are read fresh on every call (not cached at import / module-level
# constants) so a caller can flip the env var mid-process — same
# reasoning that keeps ENV_FILE resolution simple, and it makes both
# trivially monkeypatchable in tests via monkeypatch.setenv() without
# needing an importlib.reload() dance.
def audit_journal_anchor_enabled() -> bool:
    """Whether audit.append()/verify_full() should best-effort checkpoint
    (and cross-check) the audit chain tail against the systemd journal —
    an external witness OUTSIDE the case directory that a same-OS-user
    attacker can append to but not rewrite (see A1-H2). Default ON; the
    feature degrades fully gracefully to a silent no-op on any host with
    no systemd/journald/logger (CI, containers, macOS) — see
    spectre.pipeline.audit._journal_write() / _journal_read_entries()."""
    val = os.environ.get("SPECTRE_AUDIT_JOURNAL_ANCHOR", "1").strip().lower()
    return val not in ("0", "false", "no", "off", "")


def audit_hmac_key() -> bytes | None:
    """Resolve the opt-in audit-chain HMAC key from OUTSIDE the case
    directory. SPECTRE_AUDIT_HMAC_KEY (a literal secret) takes precedence
    over SPECTRE_AUDIT_HMAC_KEYFILE (a path to a file holding it, read and
    right-stripped). Neither set -> None, and the HMAC layer is OFF —
    audit.append()/verify_chain() then behave byte-identically to before
    this feature existed.

    This key defends the case-HANDOFF attacker (e.g. a copy of the case
    directory goes to opposing counsel, who gets full read/write access to
    their copy but not to wherever this key lives) — it does NOT, and can
    never, defend against the same-OS-user attacker who has access to
    whatever env var or keyfile Spectre itself read this from. Never
    sourced from, and never written into, the case directory or the audit
    rows themselves.

    IMPORTANT — what this key does NOT do: the hand-off attacker cannot
    RECOMPUTE a valid entry_hmac after tampering a row and re-deriving the
    SHA-256 chain forward (they lack the key), but they CAN simply DELETE
    the entry_hmac field from the rows they touch, since it's an ordinary
    JSON field with no cryptographic protection of its own presence.
    audit.py's verify_chain() detects a PARTIAL strip (entry_hmac missing
    after an earlier row had one — a monotonic-coverage violation) but a
    FULL strip across every row is, by design, indistinguishable from a
    chain that never used this feature. Only the external systemd-journal
    anchor (audit_journal_anchor_enabled(), when journald is reachable)
    can catch a full strip, because it independently witnesses
    entry_sha256 itself, not entry_hmac. See verify_full()'s docstring.
    """
    key = os.environ.get("SPECTRE_AUDIT_HMAC_KEY", "")
    if key:
        return key.encode("utf-8")
    keyfile = os.environ.get("SPECTRE_AUDIT_HMAC_KEYFILE", "")
    if keyfile:
        try:
            with open(keyfile, "rb") as f:
                data = f.read().strip()
        except OSError:
            return None
        if data:
            return data
    return None


# ── Case management ────────────────────────────────────────────────
def case_dir(case_id: str) -> Path:
    """Return the path for a case directory."""
    return CASES_DIR / case_id
