"""Settings and audit log for injection-guard.

Config lives in ``guard.json`` next to the plugin, created on first run with defaults, so
a user can tune it without touching Python. ``INJECTION_GUARD_MODE`` overrides the mode
for a single run (handy in CI and in demos).

Audit records are append-only JSONL in ``audit.jsonl``. They store a SHA-256 of the
offending text, never the text itself: the log is meant to prove the guard fired without
becoming a second copy of the untrusted payload.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
_CONFIG_PATH = _HERE / "guard.json"
_AUDIT_PATH = _HERE / "audit.jsonl"

_LOCK = threading.Lock()
_RECENT: list[dict[str, Any]] = []
_MAX_RECENT = 50

DEFAULTS: dict[str, Any] = {
    "mode": "enforce",
    "threshold": 6,
    # Tools whose output is fetched from outside the trust boundary. Prefix matching:
    # "browser_" covers every browser_* tool, "gmail" covers gmail_*.
    "protected_tools": [
        "web_extract", "web_search", "browser_", "read_file", "read_url",
        "fetch", "gmail", "email", "ocr",
    ],
    # Set to true to screen every tool result, including terminal and file writes.
    "protect_all_tools": False,
    "log_clean": False,
    "max_scan_chars": 2_000_000,
}


def _load() -> dict[str, Any]:
    cfg = dict(DEFAULTS)
    try:
        if _CONFIG_PATH.exists():
            cfg.update(json.loads(_CONFIG_PATH.read_text(encoding="utf-8")))
    except Exception:
        pass
    env_mode = os.environ.get("INJECTION_GUARD_MODE", "").strip().lower()
    if env_mode in ("enforce", "report", "off"):
        cfg["mode"] = env_mode
    return cfg


def settings() -> dict[str, Any]:
    return _load()


def is_protected(tool_name: str, cfg: dict[str, Any] | None = None) -> bool:
    cfg = cfg or _load()
    if cfg.get("protect_all_tools"):
        return True
    name = (tool_name or "").lower()
    return any(name.startswith(prefix.lower()) for prefix in cfg.get("protected_tools") or [])


def record(tool_name: str, verdict, action: str) -> dict[str, Any]:
    """Append one audit entry and return it."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "tool": tool_name,
        "score": verdict.score,
        "signals": verdict.families(),
        "hidden_chars": verdict.hidden_chars,
        "base64_blobs": verdict.base64_blobs,
        "action": action,
    }
    with _LOCK:
        _RECENT.append(entry)
        del _RECENT[:-_MAX_RECENT]
        try:
            with _AUDIT_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass
    return entry


def recent(limit: int = 20) -> list[dict[str, Any]]:
    with _LOCK:
        return list(_RECENT[-limit:])


def stats() -> dict[str, Any]:
    cfg = _load()
    items = recent(_MAX_RECENT)
    by_tool: dict[str, int] = {}
    by_signal: dict[str, int] = {}
    for it in items:
        by_tool[it["tool"]] = by_tool.get(it["tool"], 0) + 1
        for s in it["signals"]:
            by_signal[s] = by_signal.get(s, 0) + 1
    return {
        "mode": cfg.get("mode"),
        "threshold": cfg.get("threshold"),
        "blocked_total": len(items),
        "by_tool": by_tool,
        "by_signal": by_signal,
        "recent": items[-5:],
        "audit_path": str(_AUDIT_PATH),
    }


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
