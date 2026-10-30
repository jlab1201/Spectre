"""Single source of truth for what an IOC-shaped literal is (Track E1).

The inviolable rule ("the AI only explains findings it never invents") is
enforced by grounding: any IOC-shaped literal in model-written prose must be
traceable to deterministic finding data, or it is stripped. That token
definition must exist in exactly ONE place so the per-finding explainer
(explain.py) and the report synthesizer (report_synthesize.py) ground against
the same vocabulary. This module is that place.
"""
from __future__ import annotations

import functools
import json
import re
import unicodedata

# ── Token classes ──────────────────────────────────────────────────────
# Conservative by design: over-matching strips a harmless mention; the cost
# of protecting the inviolable rule. Same tradeoff documented in explain.py.

IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# IPv6 (RFC 4291 incl. compressed "::" forms). Each alternative captures the
# FULL address — a prefix before "::" is never dropped, so two addresses that
# share only a suffix (fe80::abcd vs 1234::abcd) yield distinct tokens and
# cannot cross-ground. The suffix is folded into the SAME alternative as the
# prefix (as a greedy optional group) rather than a separate later
# alternative: Python's `|` takes the first alternative that matches at a
# position, not the longest, so a standalone "prefix::" alternative would
# match and stop before a later "prefix::suffix" alternative ever got a
# chance — silently reproducing the original truncation bug. Embedded-IPv4
# and zone-id forms are intentionally out of scope (conservative: a miss
# strips nothing, it does not mis-ground).
IPV6_RE = re.compile(
    r"(?:"
    r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"                       # full 8-group, no ::
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"                                    # prefix::
    r"(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"                #   [suffix]
    r"|:(?::[0-9A-Fa-f]{1,4}){1,7}"                                    # ::suffix (no prefix)
    r"|::"                                                              # bare ::
    r")"
)

# URL captured whole (its host is also caught separately by DOMAIN_RE).
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)

# Domain: label.label(.tld). Also matches filename-shaped tokens
# (rundll32.exe) — intentional, mirrors explain.py's historical behavior.
#
# L4 (ReDoS): the old `\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b` retried from every
# label start inside a long dotted run ("1."*20000), each retry scanning to
# the run's end — quadratic. A match may now only START at the beginning of
# a label chain (not after a label char, "-", or "label."): if a later start
# in the same chain could match, the chain start matches too (its extra
# labels are all `[a-z0-9-]+\.`), so no domain is lost. Label and TLD are
# possessive (a label must be followed by ".", a TLD by a non-alnum, so
# giving characters back can never succeed). Linear time. The end boundary
# is "not alnum" (was \b), so a markdown-italic `_evil.com_` now matches.
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?<![A-Za-z0-9-]\.)(?:[a-z0-9-]++\.)+[a-z]{2,}+(?![A-Za-z0-9])",
    re.IGNORECASE)

# Hashes: md5 (32), sha1 (40), sha256 (64) hex runs.
HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b")

# User-Agent product tokens: a known product name followed by "/" or " " and
# a version number. Requiring a version avoids matching the bare English word
# "Chrome"/"Safari". Covers the case-001 fabrication (Mozilla/4.0, MSIE 7.0,
# Trident/4.0) and common tool UAs.
UA_RE = re.compile(
    r"\b(?:Mozilla|MSIE|Trident|AppleWebKit|Chrome|Safari|Edge|Opera|"
    r"curl|Wget|python-requests|Go-http-client|okhttp|libredtail-http|zgrab)"
    r"[/ ]\d[\w.]*",
    re.IGNORECASE,
)

# Threat-actor designators and known malware families. Deliberately a closed
# vocabulary plus structured designators — an open "capitalized word" heuristic
# would flag ordinary prose and strip legitimate sentences. Extend the family
# list as the knowledge base grows; unknown families simply stay ungrounded-
# safe (not flagged), which is the conservative direction: a missed family
# means prose survives, never that a fabricated finding is created.
#
# Demonstrated cost, ship-as-is by human decision: the vocabulary mixes actors
# (Lazarus), malware families (Emotet, Conti), and tools (Cobalt Strike,
# Mimikatz) — and tool names legitimately appear in non-attribution forensic
# prose. Sharpest case, verified by direct test: a NEGATIVE finding — "No
# Cobalt Strike artifacts were found in memory." — extracts {'cobalt strike'}
# and is stripped, and can never be grounded by construction, because nothing
# was found and so nothing appears in any finding. Separately, TA\d{3,4},
# FIN\d{1,2}, and UNC\d{3,5} collide with plausible casework tokens: "Task
# TA405", "Ticket FIN12", hostname fin7-backup01, username ta307. Both fail in
# the safe direction — over-strip, never admit a fabricated finding — per the
# philosophy above.
ACTOR_RE = re.compile(
    r"\b(?:APT\s?\d{1,3}"
    r"|UNC\d{3,5}"
    r"|FIN\d{1,2}"
    r"|TA\d{3,4}"
    r"|Lazarus|Emotet|TrickBot|QakBot|Cobalt\s?Strike|Mimikatz"
    r"|Conti|LockBit|BlackCat|ALPHV|REvil|Ryuk)\b",
    re.IGNORECASE,
)

# Extract order matters only for readability; results are a set.
_CASE_SENSITIVE = (IPV4_RE, IPV6_RE, HASH_RE)   # keep original case
_CASE_FOLD = (URL_RE, DOMAIN_RE, UA_RE, ACTOR_RE)   # normalize to lowercase


# ── Defanging / evasion normalization (WS7a sub-task 2) ───────────────
# A2/A3 review: the literal-character regexes above miss threat-intel-style
# defanged notation (`1[.]2[.]3[.]4`, `hxxp://`, `evil(dot)com`) and
# zero-width-space-injected tokens (`185.220.101​.42`) — both make an
# IOC-shaped literal simply not match, so `ungrounded_literals()` returns an
# empty set and a fabricated IOC in that shape sails through the grounding
# check untouched. Fix: normalize BEFORE matching, and apply the identical
# normalization to both the grounded set and the candidate text. Both
# callers (grounded_tokens and ungrounded_literals) funnel through
# extract_iocs(), so normalizing once here covers both sides of every
# comparison in explain.py and report_synthesize.py identically.


_NFKC_KEEP = ("µ", "…")
_NFKC_KEEP_SPLIT_RE = re.compile("([µ…])")


def normalize_unicode(text: str) -> str:
    """NFKC + strip every Cf (format) char. The ONLY rewrite ever applied to
    text that is kept in output: NFKC is the baseline the character policy
    is defined on, and Cf chars (zero-width, soft hyphen, bidi overrides)
    are invisible — a bidi override would otherwise let the displayed order
    differ from the order the validators judged. It never folds one
    visible character into a different one (no confusable, dash, dot or
    defang folding — W2-A round 4, L1)."""
    if not text:
        return text
    if text.isascii():
        return unicodedata.normalize("NFKC", text)
    # µ (MICRO SIGN) and … are whitelisted and read the same as their NFKC
    # forms (Greek μ, "..."), so they are kept as written rather than
    # rewritten — the text judged is still exactly the text shown.
    out = "".join(p if p in _NFKC_KEEP else unicodedata.normalize("NFKC", p)
                  for p in _NFKC_KEEP_SPLIT_RE.split(text) if p)
    return "".join(c for c in out if unicodedata.category(c) != "Cf")


# ── Fail-closed character policy: a WHITELIST (W2-A round 5) ─────────
# The text validators judge is English DFIR prose. Chasing lookalikes
# glyph by glyph (Cherokee Ꭲ, DOWN TACK ⊤, SYRIAC ܂, combining strikes,
# braille blank, ...) is a finite denylist against an open alphabet, so
# the policy is a whitelist over the WHOLE charset: after NFKC (Cf chars
# stripped) every character of validated prose must be
#   * printable ASCII, or ASCII / line-separator whitespace;
#   * a Latin-1 / Latin Extended-A letter (U+00C0-U+017F, minus × ÷);
#   * one of a small list of typographic characters (_TYPOGRAPHIC). The
#     bullet is allowed only when it does not sit between two
#     alphanumerics (185•220•101•42 is a dotted IP to a reader).
# Anything else — every combining mark (Mn/Me), symbol, enclosed or
# regional letter, non-Latin letter, braille blank, unusual dot — is a
# violation and the sentence is dropped. Exception: a WHOLE token
# (delimited by whitespace or ASCII punctuation) that occurs verbatim as a
# token of the case's deterministic data (a real IDN / homograph IOC such
# as a Cyrillic "pаypal-update.com") is allowed, and is kept in its
# ORIGINAL characters, never folded to Latin.
# U+2010/U+2011 hyphens are common in LLM prose; canonicalize() folds them
# to "-" before ID/MITRE matching, so allowing them opens no bypass.
_TYPOGRAPHIC = "‘’“”\u2010\u2011–—…•°×µμσΔ±≥≤≈→©"
_DISALLOWED_RE = re.compile(
    "[^\t\n\x0b\x0c\r\x20-\x7e\x85  "
    "À-ÖØ-öø-ſ" + _TYPOGRAPHIC + "]")
_BULLET_BETWEEN_ALNUM_RE = re.compile(r"(?<=[^\W_])•(?=[^\W_])")
# Token delimiters for the verbatim exemption: whitespace + ASCII punctuation.
_TOKEN_DELIM_RE = re.compile(r"[\s!-/:-@\[-`{-~]")
_TOKEN_SPLIT_RE = re.compile(r"[\s!-/:-@\[-`{-~]+")


def _policy_tokens(text: str):
    for t in _TOKEN_SPLIT_RE.split(text):
        t = t.strip(_TYPOGRAPHIC)
        if t:
            yield t


def build_corpus(*objs, skip_keys: tuple[str, ...] = ("description",)) -> frozenset:
    """Every whole token (keys and values) of the deterministic data, NFKC
    + Cf-stripped, split on whitespace / ASCII punctuation. Values under
    `skip_keys` (the model-writable description) are excluded."""
    toks: set[str] = set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in skip_keys:
                    continue
                walk(k)
                walk(v)
        elif isinstance(o, (list, tuple, set)):
            for v in o:
                walk(v)
        elif o is not None:
            s = normalize_unicode(str(o))
            if not s.isascii():
                toks.update(_policy_tokens(s))

    for obj in objs:
        walk(obj)
    return frozenset(toks)


def policy_violations(text: str, corpus=frozenset()) -> list[str]:
    """Whole tokens of `text` (NFKC, Cf stripped) holding a character
    outside the whitelist that are not verbatim tokens of `corpus`
    (build_corpus). Empty = clean."""
    t = normalize_unicode(text or "")
    if not t:
        return []
    hits = sorted({m.start() for m in _DISALLOWED_RE.finditer(t)}
                  | {m.start() for m in _BULLET_BETWEEN_ALNUM_RE.finditer(t)})
    bad: list[str] = []
    end = -1
    for i in hits:
        if i < end:
            continue          # same token as the previous hit
        a = i
        while a > 0 and not _TOKEN_DELIM_RE.match(t[a - 1]):
            a -= 1
        b = i + 1
        while b < len(t) and not _TOKEN_DELIM_RE.match(t[b]):
            b += 1
        end = b
        tok = t[a:b].strip(_TYPOGRAPHIC)
        if tok and tok in corpus:
            continue
        bad.append(tok or t[i])
    return bad


foreign_words = policy_violations   # back-compat name


POLICY_REASON = "disallowed character in validated text"


# ── canonicalize(): the ONE matching normalizer ────────────────────────
# Every AI-output seam (report V1/V2/V3/V5/V6/V10/V11, explain V2/V5, the
# Phase-5 adversarial review, IOC grounding) DECIDES on this text. It is
# detection-grade only: output is never rewritten into it. canonical_map()
# also returns, for every canonical character, the span of original
# characters it came from, so a sentence or a single token can be cut or
# replaced in the ORIGINAL text.
#
# Targeted confusable table — defense in depth only; the character policy
# above is the primary control. Latin lookalikes from Cyrillic, Greek,
# Armenian, the small-capital block, plus Latin-1 / Extended-A letters
# with no decomposition (Ø, Ŧ, Ł, ...), which the policy allows.
_CONFUSABLES = str.maketrans({
    # Cyrillic upper
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "Ү": "Y", "Ѕ": "S",
    "І": "I", "Ј": "J", "Ԛ": "Q", "Ԝ": "W", "Ӏ": "I",
    # Cyrillic lower
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o",
    "р": "p", "с": "c", "т": "t", "х": "x", "у": "y", "ү": "y", "ѕ": "s",
    "і": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l",
    "ɡ": "g",
    # Greek upper
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "Ϝ": "F", "Ϲ": "C", "Ϳ": "J",
    # Greek lower
    "α": "a", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ϲ": "c", "ϳ": "j",
    # Armenian / misc Latin lookalikes
    "օ": "o", "ս": "u", "ı": "i", "ȷ": "j",
    # Latin-1 / Extended-A letters with no decomposition (policy-allowed)
    "Ø": "O", "ø": "o", "Ŧ": "T", "ŧ": "t", "Ł": "L", "ł": "l", "Đ": "D",
    "đ": "d", "Ħ": "H", "ħ": "h", "ĸ": "k", "Ŋ": "N", "ŋ": "n", "Œ": "OE",
    "œ": "oe", "Æ": "AE", "æ": "ae", "Þ": "P", "þ": "p", "ß": "ss",
    # Latin small capitals
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ꜰ": "f", "ɢ": "g",
    "ʜ": "h", "ɪ": "i", "ᴊ": "j", "ᴋ": "k", "ʟ": "l", "ᴍ": "m", "ɴ": "n",
    "ᴏ": "o", "ᴘ": "p", "ʀ": "r", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u", "ᴠ": "v",
    "ᴡ": "w", "ʏ": "y", "ᴢ": "z",
})

# Every dash-like codepoint NFKC leaves alone.
_DASH_VARIANTS_RE = re.compile(
    "[‐-―−⁃˗➖﹘﹣－⸺⸻]")

# Every dot-like separator NFKC leaves alone.
_ALL_DOT_VARIANTS_RE = re.compile(
    "[。｡․﹒．··‧∙⋅"
    "・･⸱⸳᛫]")


@functools.lru_cache(maxsize=8192)
def _fold_char(c: str) -> str:
    """Per-character detection fold: NFKD; drop Cf/Mn/Me (format chars and
    combining marks); confusable table; dash/dot variants."""
    d = unicodedata.normalize("NFKD", c)
    d = "".join(x for x in d if unicodedata.category(x) not in ("Cf", "Mn", "Me"))
    d = d.translate(_CONFUSABLES)
    d = _DASH_VARIANTS_RE.sub("-", d)
    return _ALL_DOT_VARIANTS_RE.sub(".", d)


# TLDs for the " dot " word form between labels. English words that double
# as TLDs (local, live, online, site, app, ...) are deliberately absent.
_DOT_WORD_TLDS = (r"(?:com|net|org|info|biz|io|ru|cn|su|xyz|onion|pw|cc|tk|ml|ga|"
                  r"cf|gq|ws|tv|ly|de|nl|uk|fr|gov|edu|mil|arpa|icu|moe|top)")

# Structural folds, applied in order and repeated to a fixpoint (bounded).
# \s is Unicode whitespace: \n, \r, U+2028/2029 and (after NFKD) NBSP.
# R3-4: there is NO "word. tld" join — a dot followed by whitespace is
# only fused when there is whitespace on BOTH sides of it
# ("evil-c2 . com") or it sits between two digit groups ("185. 220"),
# so ordinary sentence boundaries ("observed. Local …") never fuse.
_CANON_SUBS = (
    # Bracketed defang, any nesting / inner spacing: [.] [[.]] { . } (dot) [dot] <.>
    # ((?<!\s) anchors the leading \s* at a whitespace-run start: linear.)
    (re.compile(r"(?<!\s)\s*[\[({<]+\s*(?:\.|dot)\s*[\])}>]+\s*", re.IGNORECASE), "."),
    (re.compile(r"[\[(]\s*:\s*[\])]"), ":"),
    (re.compile(r"[\[(]\s*at\s*[\])]", re.IGNORECASE), "@"),
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    # "185 dot 220" (word form between digit groups)
    (re.compile(r"(?<=\d)\s*\bdot\b\s*(?=\d)|(?<=\d)\s+dot(?=\d)|(?<=\d)dot\s+(?=\d)",
                re.IGNORECASE), "."),
    # "evil-c2 dot com" / "evil DOT com"
    (re.compile(r"(?<=[A-Za-z0-9-])\s+dot\s+(?=" + _DOT_WORD_TLDS + r"\b)", re.IGNORECASE), "."),
    (re.compile(r"(?<=[A-Za-z0-9-])\s+DOT\s+(?=[A-Za-z0-9])"), "."),
    # "185 . 220", "185.\n220", "185\n.220" — whitespace around a dot between digits
    (re.compile(r"(?<=\d)(?:\s+\.\s*|\.\s+)(?=\d)"), "."),
    # "evil-c2 . com" — whitespace on BOTH sides of the dot
    (re.compile(r"(?<=[A-Za-z0-9-])\s+\.\s+(?=[A-Za-z0-9])"), "."),
)
_CANON_MAX_PASSES = 8


def _msub(rx, repl: str, s: str, spans):
    """re.sub that also maintains the canonical→original span map."""
    if spans is None:
        return rx.sub(repl, s), None
    out: list[str] = []
    new_spans: list = []
    last = 0
    for m in rx.finditer(s):
        a, b = m.start(), m.end()
        out.append(s[last:a])
        new_spans.extend(spans[last:a])
        out.append(repl)
        if b > a:
            sp = (spans[a][0], spans[b - 1][1])
        else:
            sp = (spans[a][0], spans[a][0]) if a < len(spans) else (0, 0)
        new_spans.extend([sp] * len(repl))
        last = b
    if not out:
        return s, spans
    out.append(s[last:])
    new_spans.extend(spans[last:])
    return "".join(out), new_spans


def _canon(text: str, track: bool):
    if not text:
        return text or "", ([] if track else None)
    if text.isascii():
        out = text
        spans = [(i, i + 1) for i in range(len(text))] if track else None
    else:
        pieces: list[str] = []
        spans = [] if track else None
        for i, c in enumerate(text):
            f = c if c < "\x80" else _fold_char(c)
            pieces.append(f)
            if track and f:
                spans.extend([(i, i + 1)] * len(f))
        out = "".join(pieces)
    for _ in range(_CANON_MAX_PASSES):
        prev = out
        for rx, repl in _CANON_SUBS:
            out, spans = _msub(rx, repl, out, spans)
        if out == prev:
            break
    return out, spans


def canonicalize(text: str) -> str:
    """The single shared canonical form every validator matches on.

    Per character: NFKD, drop Cf / combining marks, fold the confusable
    table and every dash/dot variant. Then structural folds to a fixpoint:
    bracketed / word defangs ([.] [[.]] {.} (dot) [dot] " dot " hxxp),
    whitespace (any, incl. line breaks) around a dot between digit groups,
    and a dot with whitespace on BOTH sides between labels. Idempotent.
    Ordinary ASCII prose is returned unchanged. Detection-grade only —
    never written back to output."""
    return _canon(text, False)[0]


def canonical_map(text: str) -> tuple[str, list[tuple[int, int]]]:
    """(canonical text, span map): canonical char i came from
    text[spans[i][0]:spans[i][1]]."""
    return _canon(text or "", True)


class Sentence:
    """One sentence: its ORIGINAL text, its canonical text, and the map from
    canonical offsets to original offsets (local to `orig`)."""
    __slots__ = ("orig", "canon", "spans")

    def __init__(self, orig: str, canon: str, spans: list[tuple[int, int]]):
        self.orig, self.canon, self.spans = orig, canon, spans

    def replace(self, repls) -> str:
        """Replace canonical spans [(start, end, new_text), ...] in the
        ORIGINAL text — every character outside a replaced token keeps its
        original spelling."""
        # One linear pass (perf: 100k+ replacements in a 1 MB field would
        # be quadratic with repeated slicing).
        parts: list[str] = []
        last = 0
        for a, b, new in sorted(repls, key=lambda r: r[0]):
            oa, ob = self.spans[a][0], self.spans[b - 1][1]
            if oa < last:
                continue      # overlapping candidate — already replaced
            parts.append(self.orig[last:oa])
            parts.append(new)
            last = ob
        parts.append(self.orig[last:])
        return "".join(parts)


_SENTENCE_BOUNDARY_RE = re.compile(r"(?<=[.!?])\s+")


def sentences(text: str) -> list[Sentence]:
    """Split on CANONICAL text (so a boundary never cuts an IOC that
    canonicalization fuses — B2) and map each sentence back to its original
    characters."""
    canon, spans = canonical_map(text or "")
    out: list[Sentence] = []

    def emit(a: int, b: int):
        seg = canon[a:b]
        lead = len(seg) - len(seg.lstrip())
        end = len(seg.rstrip())
        if lead >= end:
            return
        ca, cb = a + lead, a + end
        oa, ob = spans[ca][0], spans[cb - 1][1]
        out.append(Sentence(text[oa:ob], canon[ca:cb],
                            [(s - oa, e - oa) for s, e in spans[ca:cb]]))

    start = 0
    for m in _SENTENCE_BOUNDARY_RE.finditer(canon):
        emit(start, m.start())
        start = m.end()
    emit(start, len(canon))
    return out


def split_sentences(text: str) -> list[str]:
    """Canonical sentences of `text` (split after canonicalization)."""
    return [s.canon for s in sentences(text)]


def edit_sentences(text: str, fn) -> tuple[str, bool]:
    """Apply `fn(Sentence)` to each sentence. `fn` returns None (keep the
    original sentence unchanged), "" (drop it) or a replacement built from
    the ORIGINAL (Sentence.replace). A text with no change is returned
    byte-for-byte; a changed one is the kept original sentences joined by a
    space."""
    if not isinstance(text, str) or not text:
        return text, False
    kept: list[str] = []
    changed = False
    for s in sentences(text):
        r = fn(s)
        if r is None:
            kept.append(s.orig)
            continue
        changed = True
        if r:
            kept.append(r)
    return (" ".join(kept) if changed else text), changed


def redact_candidates(text: str, candidates, decide) -> tuple[str, list[str]]:
    """WHOLE-FIELD token redaction (W2-A round 5, LOW-2): `candidates` is
    mitre_candidates / finding_id_candidates, run on the canonical form of
    the whole field — so a token spanning a sentence boundary ("tagged T.
    1003 events") or created by a later sentence drop is still seen.
    `decide(token)` returns a replacement string or None (keep). Tokens are
    replaced in the ORIGINAL text; every other character keeps its
    spelling. Returns (text, replaced_tokens); unchanged text is returned
    as-is."""
    if not isinstance(text, str) or not text:
        return text, []
    hits = [(a, b, tok, r) for a, b, tok in candidates(canonicalize(text))
            if (r := decide(tok)) is not None]
    if not hits:
        return text, []
    canon, spans = canonical_map(text)
    out = Sentence(text, canon, spans).replace([(a, b, r) for a, b, _, r in hits])
    return out, [tok for _, _, tok, _ in hits]


# ── MITRE technique candidates (on canonical text) ────────────────────
# R3-1: a candidate is any T-anchored 4-digit group (T/t, then up to 8
# _MITRE_SEP separators, then 4 digits, optional .NNN), where the
# digits may be written with the letter lookalikes O/o (0) and I/i/l/L/|
# (1) — at least two real digits are required so a word like "Tool1"
# never matches. Belt-and-braces: a bare sub-technique shape NNNN.NNN, and
# a 4-digit number right after the word technique / sub-technique / TTP,
# are candidates too. A bare 4-digit number with no T-like prefix and no
# .NNN (a year, a port, a PID) is NOT. A "/t 3600" Windows switch (slash
# before the T, no sub-technique) is not a technique. Any candidate that is
# not an exact allowed ID is a violation.
_MD = r"[0-9OoIl|]"
# Separators between the T and the digits (R4-1): whitespace, the ASCII
# marks : . _ / - * ` ~ ' " ( ) [ ] { } < > # and the whitelisted
# typographic quotes/dashes/bullet/ellipsis. "+" "=" "," ";" are NOT
# separators ("T+1200 s" is a timeline offset, not a technique).
_MITRE_SEP = "[\\s:._/\\-*`~'\"()\\[\\]{}<>#‘’“”–—•…]"
MITRE_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])T(?P<sep>" + _MITRE_SEP + r"{1,8})?(?P<base>" + _MD + r"{4})"
    r"(?:\.(?P<sub>" + _MD + r"{3}))?(?![0-9|])",
    re.IGNORECASE)
_MITRE_SUB_SHAPE_RE = re.compile(
    r"(?<![\d.,])(?P<base>\d{4})\.(?P<sub>\d{3})(?!\d)(?!\.\d)"
    r"(?!\s*(?:ms|s|secs?|seconds?|mins?|minutes?|h|hrs?|hours?|bytes?|b|kb|mb|gb|"
    r"kib|mib|gib|%|hz|khz|mhz|x)\b)",
    re.IGNORECASE)
_MITRE_CONTEXT_RE = re.compile(
    r"\b(?:sub-?techniques?|techniques?|TTPs?)\b(?:\s+(?:ID|number|no\.?))?"
    r"[\s:#(]{1,4}(?P<base>\d{4})(?:\.(?P<sub>\d{3}))?(?!\d)",
    re.IGNORECASE)
_MD_TABLE = str.maketrans({"O": "0", "o": "0", "I": "1", "i": "1", "l": "1",
                           "L": "1", "|": "1"})


def _mitre_id(base: str, sub: str | None) -> str:
    return "T" + base.translate(_MD_TABLE) + (("." + sub.translate(_MD_TABLE)) if sub else "")


def mitre_candidates(canon: str) -> list[tuple[int, int, str]]:
    """(start, end, canonical ID) for every MITRE candidate in CANONICAL
    text, non-overlapping, in order."""
    found: list[tuple[int, int, str]] = []
    for m in MITRE_TOKEN_RE.finditer(canon):
        base, sub = m.group("base"), m.group("sub")
        if sum(ch.isdigit() for ch in base + (sub or "")) < 2:
            continue
        if not sub and m.start() > 0 and canon[m.start() - 1] == "/":
            continue   # "/t 3600" — a Windows switch, not a technique
        found.append((m.start(), m.end(), _mitre_id(base, sub)))
    for rx in (_MITRE_CONTEXT_RE, _MITRE_SUB_SHAPE_RE):
        for m in rx.finditer(canon):
            a, b = m.start("base"), m.end()
            if any(a < e and s < b for s, e, _ in found):
                continue
            found.append((a, b, _mitre_id(m.group("base"), m.group("sub"))))
    return sorted(found)


def mitre_tokens(text: str) -> list[str]:
    """Canonical MITRE IDs mentioned anywhere in `text`."""
    return [t for _, _, t in mitre_candidates(canonicalize(text or ""))]


# ── Finding IDs (on canonical text) ───────────────────────────────────
# B4/L5: dash variants are already "-"; the F may be lower-case, and the
# separator may be "-" or "." (the same one twice; the dotted form needs
# 3+ digit groups so "Appendix F.2.1" is not an ID). Lisu ꓝ and other
# non-Latin F lookalikes are handled by the character policy.
FINDING_ID_RE = re.compile(
    r"(?<![A-Za-z0-9])[Ff][ \t_]{0,3}(?P<sep>[-.])[ \t_]{0,3}(?P<a>\d+)"
    r"[ \t_]{0,3}(?P=sep)[ \t_]{0,3}(?P<b>\d+)(?!\d)")


def finding_id_of(m: "re.Match") -> str:
    return f"F-{m.group('a')}-{m.group('b')}"


def finding_id_candidates(canon: str) -> list[tuple[int, int, str]]:
    out = []
    for m in FINDING_ID_RE.finditer(canon):
        if m.group("sep") == "." and (len(m.group("a")) < 3 or len(m.group("b")) < 3):
            continue
        out.append((m.start(), m.end(), finding_id_of(m)))
    return out


def finding_ids(text: str) -> list[str]:
    """Canonical finding IDs mentioned anywhere in `text`."""
    return [t for _, _, t in finding_id_candidates(canonicalize(text or ""))]


# Caveat-signal phrasings: an evidentiary "does not prove / is not evidence
# of" claim. Matched on canonical text; words may be joined by any run of
# whitespace, "-" or "_" (R3-5: "does-not-prove").
_W = r"[\s\-_]+"


def _phrase_re(pattern: str) -> str:
    return pattern.replace(r"\s+", _W)


CAVEAT_SIGNAL_RE = re.compile(_phrase_re(
    r"\b(?:does\s+not\s+prove|do\s+not\s+prove|does\s+not\s+establish"
    r"|is\s+not\s+proof\s+of|are\s+not\s+proof\s+of|is\s+not\s+evidence\s+of"
    r"|are\s+not\s+evidence\s+of|cannot\s+be\s+concluded\s+from"
    r"|does\s+not\s+confirm|do\s+not\s+confirm)\b"),
    re.IGNORECASE,
)

# Certainty over-claims that contradict the FK caveats (B5). Narrow on
# purpose: explicit proof/certainty language only, never "shows"/"confirms".
OVERCLAIM_RE = re.compile(_phrase_re(
    r"\b(?:conclusive(?:ly)?\s+(?:proof|evidence|proves?)"
    r"|definitive(?:ly)?\s+(?:proof|evidence|proves?)"
    r"|(?:is|are)\s+proof\s+(?:of|that)"
    r"|irrefutabl[ey]|beyond\s+(?:any\s+|a\s+|all\s+)?(?:reasonable\s+)?doubt"
    r"|needs?\s+no\s+(?:further\s+)?corroboration"
    r"|(?:requires?|required)\s+no\s+(?:further\s+)?corroboration)\b"),
    re.IGNORECASE,
)


def caveat_key(text: str) -> str:
    """Comparison key for an exact caveat-sentence match: canonical text,
    whitespace collapsed, terminal punctuation ignored."""
    t = re.sub(r"\s+", " ", canonicalize(text or "")).strip()
    return t.rstrip(".!?;: ").strip()


def _normalize(text: str) -> str:
    """IOC-matching pre-pass = canonicalize(). Applied identically to the
    grounded set and to candidate text, so a legitimately defanged or
    Unicode-spelled real IOC never falsely flags."""
    return canonicalize(text)


# ── ASCII digit lookalikes inside IOCs (R4-3) ──────────────────────────
# `l85.220.101.42` (l for 1), `185.22O.1O1.42` (O for 0), a sha256 with an
# `O`: none parse under IPV4_RE / HASH_RE, so nothing was stripped, yet a
# reader reads them as the IOC. Such a token is an IOC candidate in its
# ORIGINAL spelling: it is grounded only when that exact spelling occurs in
# deterministic data (grounded_tokens runs the same extraction), so a
# lookalike of a grounded IOC is stripped as well. Detection only; output is
# never rewritten. False-positive guards: a substitution char must be
# present, >= 2 real digits, every folded octet <= 255, an octet never
# starts/ends with "|" (markdown tables), and alnum/dotted boundaries so
# "v1.O", "lOO" or a 5-part version never match.
_LOOKALIKE_FOLD = str.maketrans({"l": "1", "I": "1", "|": "1", "O": "0"})
_OCT_FIRST = r"[0-9lIO](?:[0-9lIO|]{0,1}[0-9lIO])?"
_OCT_LAST = r"[0-9lIO](?:[0-9lIO|]{0,1}[0-9lIO])?"
_OCT_MID = r"[0-9lIO|]{1,3}"
_LOOKALIKE_IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9|])(?<![A-Za-z0-9]\.)"
    + _OCT_FIRST + r"\." + _OCT_MID + r"\." + _OCT_MID + r"\." + _OCT_LAST
    + r"(?![A-Za-z0-9|])(?!\.[A-Za-z0-9])")
_LOOKALIKE_HASH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[0-9a-fA-FlIO]{64}|[0-9a-fA-FlIO]{40}|[0-9a-fA-FlIO]{32})"
    r"(?![A-Za-z0-9_])")
# Domain whose TLD swaps 0/1 for o/l/i ("evil-c2.c0m"); only folded 3+ letter
# TLDs from the short " dot " list count, so "mp3", "x64", "srv.n1" never match.
_LOOKALIKE_TLD_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?<![A-Za-z0-9-]\.)(?:[a-z0-9-]++\.)+"
    r"([a-z0-9]{3,6})(?![A-Za-z0-9])", re.IGNORECASE)
_DOT_WORD_TLDS_RE = re.compile(_DOT_WORD_TLDS + r"\Z")


def _lookalike_iocs(text: str) -> set[str]:
    """IOC-shaped tokens with letter-for-digit substitutions (R4-3), in their
    original spelling. `text` is already canonical."""
    out: set[str] = set()
    for m in _LOOKALIKE_IPV4_RE.finditer(text):
        tok = m.group(0)
        if sum(c.isdigit() for c in tok) < 2 or not re.search(r"[lIO|]", tok):
            continue
        if all(int(o.translate(_LOOKALIKE_FOLD)) <= 255 for o in tok.split(".")):
            out.add(tok)
    for m in _LOOKALIKE_HASH_RE.finditer(text):
        tok = m.group(0)
        if re.search(r"[lIO]", tok) and sum(c.isdigit() for c in tok) >= 2:
            out.add(tok)
    for m in _LOOKALIKE_TLD_RE.finditer(text):
        tld = m.group(1).lower()
        if re.search(r"[01]", tld) and re.search(r"[a-z]", tld):
            folded = tld.replace("0", "o").replace("1", "l")
            if _DOT_WORD_TLDS_RE.match(folded) or _DOT_WORD_TLDS_RE.match(
                    tld.replace("0", "o").replace("1", "i")):
                out.add(m.group(0).lower())
    return out


def extract_iocs(text: str) -> set[str]:
    """Return the set of IOC-shaped tokens in `text` (normalized)."""
    if not text:
        return set()
    text = _normalize(text)
    tokens: set[str] = set()
    for rx in _CASE_SENSITIVE:
        tokens |= set(rx.findall(text))
    for rx in _CASE_FOLD:
        tokens |= {m.lower() for m in rx.findall(text)}
    return tokens | _lookalike_iocs(text)


def grounded_tokens(obj, skip_keys: tuple[str, ...] = ("description",)) -> set[str]:
    """All IOC-shaped literals in `obj` (dict/list/str), excluding any dict
    values under `skip_keys` (e.g. the model-writable 'description')."""
    src = obj
    if isinstance(obj, dict):
        src = {k: v for k, v in obj.items() if k not in skip_keys}
    text = json.dumps(src, default=str, ensure_ascii=False)
    return extract_iocs(text)


def ungrounded_literals(text: str, grounded: set[str]) -> set[str]:
    """IOC tokens in `text` that are absent from the `grounded` set."""
    return {t for t in extract_iocs(text) if t not in grounded}
