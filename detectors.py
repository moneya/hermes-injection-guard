"""Detection engine for injection-guard.

Deterministic, offline, no network and no LLM calls. Every rule is a compiled regex
against a text blob; each family carries a weight so a single weak signal does not trip
the guard while several medium signals do.

The scoring threshold matters more than any individual rule: a false positive costs the
user real content, a false negative costs them their machine. Defaults are tuned to flag
only when at least one strong signal or several medium ones fire together.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- unicode

# Zero-width and bidirectional control characters are almost never legitimate in tool
# output. They are the cheapest way to hide an instruction inside visible text.
_HIDDEN_CODEPOINTS = (
    (0x200B, 0x200F),  # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),  # bidi embeddings/overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # BOM used mid-document
    (0xE0000, 0xE007F),  # tag characters
)

_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

# --------------------------------------------------------------------------- families

# (family name, weight, patterns). Weight is intent, not severity: an override phrase is
# worth more than a mention of "token".
_FAMILIES: list[tuple[str, int, list[re.Pattern[str]]]] = [
    (
        "instruction_override",
        6,
        [
            re.compile(r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}\b"
                       r"(previous|prior|above|earlier|all|any|your)\b[^.\n]{0,30}"
                       r"(instruction|prompt|rule|direction|context|message)s?\b", re.I),
            re.compile(r"\b(ignore|disregard)\b[^.\n]{0,30}\b(everything|all of the above)\b", re.I),
            re.compile(r"\byour (new|real|actual|true) (instructions?|task|job|purpose|goal)\b", re.I),
        ],
    ),
    (
        # Unambiguous machine-level artifacts: raw chat-template tokens and fake control
        # markers do not appear in legitimate prose, so this family trips alone.
        "role_spoofing",
        6,
        [
            re.compile(r"<\|?\s*(im_start|im_end|system|endoftext|eot_id)\s*\|?>", re.I),
            re.compile(r"\[(OUT-OF-BAND USER MESSAGE|OUTBOUND USER MESSAGE|"
                       r"INTERNAL NOTIFICATION|GATEWAY MESSAGE)[^\]]{0,60}\]", re.I),
            re.compile(r"^\s*#{2,}\s*(instruction|system prompt|new task)s?\s*#*\s*$", re.I | re.M),
            re.compile(r"^\s*SYSTEM\s*[:：]\s", re.M),  # case-sensitive: "System: Ubuntu" is fine
        ],
    ),
    (
        # Persona shifting is real signal but also ordinary English ("you are now ready
        # to deploy"), so it only contributes toward the threshold.
        "persona_shift",
        3,
        [
            re.compile(r"\byou are (now|no longer)\b", re.I),
            re.compile(r"\b(act|behave|pretend)\b[^.\n]{0,20}\b(as if|as an?|like)\b", re.I),
            re.compile(r"\bfrom now on,? you (are|will|must)\b", re.I),
        ],
    ),
    (
        # Touching private keys, env files or a secret store has no benign reading when it
        # arrives inside fetched content, so it trips alone.
        "credential_access",
        6,
        [
            re.compile(r"\b(cat|type|read|print|dump|grep|head|tail)\b[^.\n]{0,30}"
                       r"(~/\.ssh|/\.ssh|id_rsa|id_ed25519|\.env\b|\.aws/credentials|"
                       r"keychain|credentials\.json)", re.I),
            re.compile(r"\b(api[ _-]?keys?|access[ _-]?tokens?|private keys?|passwords?|"
                       r"secrets?)\b[^.\n]{0,40}\b(send|reveal|print|output|show|leak)\b", re.I),
        ],
    ),
    (
        # Generic "send the data somewhere" is ordinary business English, so it only
        # contributes toward the threshold.
        "exfiltration",
        4,
        [
            re.compile(r"\b(send|email|post|upload|forward|transmit|leak)\b[^.\n]{0,60}\b"
                       r"(contents?|data|file|env|credentials?|api[ _-]?keys?|secrets?|tokens?|"
                       r"passwords?|\.ssh|id_rsa|\.env)\b", re.I),
            re.compile(r"\b(wget|nc|ncat|scp|rsync|curl)\b[^.\n]{0,60}(https?://|\d{1,3}\.\d{1,3}\.)", re.I),
        ],
    ),
    (
        "destructive",
        6,
        [
            re.compile(r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b", re.I),
            re.compile(r"\b(drop|truncate)\s+(table|database|schema)\b(?!\s+if\s+exists)", re.I),
            # --force-with-lease is the safe variant; only bare --force or -f count.
            re.compile(r"\bgit\s+push\b[^.\n]{0,30}(-f\b|--force(?![\w-]))", re.I),
            re.compile(r"\bmkfs\b", re.I),
            re.compile(r"\bdd\b[^.\n]{0,12}?\bif[=\s]", re.I),
            re.compile(r":\(\)\s*\{"),
            # "delete all draft invoices" is ordinary business English; only a destructive
            # object makes it a command worth intercepting.
            re.compile(r"\bdelete\s+(all|every)\b[^.\n]{0,25}\b"
                       r"(files?|data|records?|tables?|rows?|backups?|logs?|volumes?|"
                       r"databases?|snapshots?)\b", re.I),
        ],
    ),
    (
        # Concealment instructions have no legitimate reading inside fetched page content,
        # so this family trips alone.
        "concealment",
        6,
        [
            re.compile(r"<!--(?:(?!-->).){0,800}?(ignore|instruction|system|you must|"
                       r"assistant|prompt)\b(?:(?!-->).){0,800}?-->", re.I | re.S),
            re.compile(r"style\s*=\s*[\"'][^\"']*"
                       r"(color\s*:\s*(#fff|#ffffff|white)|font-size\s*:\s*0|"
                       r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0)[^\"']*[\"']", re.I),
            re.compile(r"\bdo not (tell|inform|mention|reveal)[^.\n]{0,30}\b(user|human|operator)\b", re.I),
            re.compile(r"\bwithout (telling|informing|notifying)[^.\n]{0,30}\b(user|human|operator)\b", re.I),
            re.compile(r"\b(hide|conceal|suppress)\b[^.\n]{0,30}\bfrom the user\b", re.I),
        ],
    ),
    (
        "meta_awareness",
        3,
        [
            re.compile(r"\b(if|when) you are an? (ai|llm|language model|assistant|agent)\b", re.I),
            re.compile(r"\b(language model|llm|ai assistant|autonomous agent)s?\b[^.\n]{0,40}"
                       r"\b(must|should|will|shall)\b", re.I),
            re.compile(r"\bas an ai\b", re.I),
        ],
    ),
]

VALID_MODES = ("enforce", "report", "off")


@dataclass
class Finding:
    family: str
    weight: int
    samples: list[str] = field(default_factory=list)
    spans: list[tuple[int, int]] = field(default_factory=list)


@dataclass
class Verdict:
    score: int
    findings: list[Finding]
    hidden_chars: int
    base64_blobs: int

    @property
    def flagged(self) -> bool:
        return self.score > 0

    def families(self) -> list[str]:
        return [f.family for f in self.findings]

    def summary(self) -> str:
        parts = [f"{f.family}(+{f.weight})" for f in self.findings]
        if self.hidden_chars:
            parts.append(f"hidden_unicode({self.hidden_chars})")
        if self.base64_blobs:
            parts.append(f"base64_blob({self.base64_blobs})")
        return ", ".join(parts) if parts else "clean"


def _count_hidden(text: str) -> int:
    n = 0
    for ch in text:
        cp = ord(ch)
        for lo, hi in _HIDDEN_CODEPOINTS:
            if lo <= cp <= hi:
                n += 1
                break
    return n


def scan(text: str, *, threshold: int = 6,
         exempt_families: frozenset[str] | set[str] = frozenset()) -> Verdict:
    """Score a blob of tool output. Threshold defaults to 6: one instruction-override or
    destructive hit trips it, as do two medium signals together.

    ``exempt_families`` skips whole signal families for this call. It exists for local file
    reads, where attack-shaped text is legitimate content: a migration containing DROP TABLE
    or a deploy script containing a recursive delete would otherwise be redacted, and if the
    model rewrote that file the lines would be silently destroyed.
    """
    if not text:
        return Verdict(0, [], 0, 0)

    findings: list[Finding] = []
    total = 0
    for family, weight, patterns in _FAMILIES:
        if family in exempt_families:
            continue
        samples: list[str] = []
        spans: list[tuple[int, int]] = []
        for pat in patterns:
            for m in pat.finditer(text):
                snippet = " ".join(m.group(0).split())[:90]
                if snippet and snippet not in samples:
                    samples.append(snippet)
                if m.end() > m.start():
                    spans.append((m.start(), m.end()))
                if len(samples) >= 3 and len(spans) >= 12:
                    break
            if len(samples) >= 3 and len(spans) >= 12:
                break
        if samples:
            findings.append(Finding(family, weight, samples, spans))
            total += weight

    hidden = _count_hidden(text)
    if hidden:
        # Hidden characters are a strong signal on their own but capped so a file full of
        # stray BOMs cannot alone exceed the threshold.
        total += min(hidden, 6)

    blobs = len(_BASE64_BLOB.findall(text))
    if blobs:
        total += min(blobs * 2, 4)

    if total < threshold:
        # Below threshold: keep the findings for logging but report clean so we never
        # rewrite content on a weak signal.
        return Verdict(0, findings, hidden, blobs)

    return Verdict(total, findings, hidden, blobs)
