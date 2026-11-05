"""Settings and audit log for injection-guard.

Config lives in ``<hermes home>/plugin-data/injection-guard/guard.json``, created on first
run with defaults, so a user can tune it without touching Python. ``INJECTION_GUARD_MODE``
overrides the mode for a single run (handy in CI and in demos).

State must NOT live next to the plugin: that directory is the install dir, which
``hermes plugins remove`` deletes and ``hermes plugins update`` replaces with a git pull.
Losing the audit log on update would be a silent hole in the evidence.

Audit records are append-only JSONL. They store a SHA-256 of the offending text, never the
text itself: the log is meant to prove the guard fired without becoming a second copy of
the untrusted payload.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PLUGIN_NAME = "injection-guard"

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
    # Tools that read LOCAL files the user owns. Their output may legitimately contain
    # attack-shaped text — a migration with DROP TABLE, a deploy script with rm -rf, a
    # security test case. Redacting those would corrupt the file if the model then rewrote
    # it, so the destructive family is exempt for file reads by default.
    "file_reader_tools": ["read_file", "read_url"],
    "exempt_families_for_reads": ["destructive"],
    # Set to true to screen every tool result, including terminal and file writes.
    "protect_all_tools": False,
    "log_clean": False,
    # The concealment pass is regex over the whole payload; ~200 KB keeps the worst case
    # well under a second, and no real page that needs screening is larger than that.
    "max_scan_chars": 200_000,
}


def _data_dir() -> Path:
    """Resolve the plugin data dir on every call so profile switches are followed.

    Uses the host's own storage helper when it is importable, and falls back to the same
    documented location otherwise. Deliberately no hard-coded repository path: a plugin
    must not assume where the host is installed.
    """
    try:
        from plugins.plugin_storage import plugin_data_dir

        return plugin_data_dir(PLUGIN_NAME)
    except Exception:
        pass
    try:
        from hermes_constants import get_hermes_home

        root = get_hermes_home() / "plugin-data" / PLUGIN_NAME
        root.mkdir(parents=True, exist_ok=True)
        return root
    except Exception:
        fallback = Path.home() / ".hermes" / "plugin-data" / PLUGIN_NAME
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def _config_path() -> Path:
    return _data_dir() / "guard.json"


def _audit_path() -> Path:
    return _data_dir() / "audit.jsonl"


def _load() -> dict[str, Any]:
    cfg = dict(DEFAULTS)
    try:
        path = _config_path()
        if path.exists():
            cfg.update(json.loads(path.read_text(encoding="utf-8")))
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


def is_file_reader(tool_name: str, cfg: dict[str, Any] | None = None) -> bool:
    cfg = cfg or _load()
    name = (tool_name or "").lower()
    return any(name == t.lower() or name.startswith(t.lower() + "_")
               for t in cfg.get("file_reader_tools") or [])


def exempt_families(tool_name: str, cfg: dict[str, Any] | None = None) -> frozenset[str]:
    """Families to ignore for this tool.

    Reading a local file is not the same risk as reading a fetched page: the file is the
    user's own data, and a false positive there can delete code. Only the destructive
    family is exempt, so instruction-override text in a fetched page still fires.
    """
    cfg = cfg or _load()
    if is_file_reader(tool_name, cfg):
        return frozenset(f.lower() for f in cfg.get("exempt_families_for_reads") or [])
    return frozenset()


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
            with _audit_path().open("a", encoding="utf-8") as fh:
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
        "audit_path": str(_audit_path()),
        "config_path": str(_config_path()),
    }


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
