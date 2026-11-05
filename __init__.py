"""injection-guard — prompt-injection firewall for tool output.

Registers a single ``tool_execution`` middleware. Hermes calls it around every tool
invocation; we let the tool run, then scan its result for instructions that were never
addressed to us, neutralise the hiding places, and label what remains as untrusted data.

Design rules, in priority order:

1. Never break a tool call. Every failure path returns the original result untouched.
2. Never trust the payload. Scanned text is data; the decision to rewrite it is made by
   deterministic rules, not by a model (a model that an attacker can talk to is not a
   firewall).
3. Never store the payload. Audit records keep a hash and signal counts only.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys

logger = logging.getLogger(__name__)

_TOOLSET = "safety"


def _mod(name: str):
    """Import a sibling module whether or not the plugin directory is on sys.path."""
    try:
        return importlib.import_module(name)
    except ImportError:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)
        return importlib.import_module(name)

# Keys we will treat as the textual payload of a dict-shaped tool result.
_TEXT_KEYS = ("output", "content", "text", "result", "stdout", "body", "data")


def _text_of(result):
    """Return (text, setter) for the payload inside a tool result, or (None, None)."""
    if isinstance(result, str):
        return result, None
    if isinstance(result, dict):
        for key in _TEXT_KEYS:
            value = result.get(key)
            if isinstance(value, str) and value:
                def setter(new_text, _r=result, _k=key):
                    _r[_k] = new_text
                return value, setter
    if isinstance(result, list) and result and all(isinstance(x, str) for x in result):
        return "\n".join(result), None
    return None, None


def make_middleware(ctx):
    """Build the tool_execution callback bound to this plugin context."""

    def on_tool_execution(tool_name=None, args=None, original_args=None,
                          next_call=None, **_context):
        # Single-use: runs the real tool exactly once, at this point in the chain.
        result = next_call() if callable(next_call) else {}

        try:
            cfg_mod = _mod("settings")

            cfg = cfg_mod.settings()
            if cfg.get("mode") == "off" or not cfg_mod.is_protected(tool_name, cfg):
                return result

            text, setter = _text_of(result)
            if not text:
                return result

            limit = int(cfg.get("max_scan_chars") or 2_000_000)
            if len(text) > limit:
                text = text[:limit]

            detectors = _mod("detectors")
            sanitizer = _mod("sanitizer")

            verdict = detectors.scan(text, threshold=int(cfg.get("threshold") or 6))
            if not verdict.flagged:
                if cfg.get("log_clean"):
                    logger.debug("injection-guard: %s clean", tool_name)
                return result

            # Order matters: redact spans against the ORIGINAL text (positions are computed
            # on it), then strip the mechanical hiding places.
            redacted_text, span_count = sanitizer.redact_spans(text, verdict)
            clean_text, removed = sanitizer.neutralise(redacted_text)
            removed["spans"] = span_count
            action = "report" if cfg.get("mode") == "report" else "enforced"

            if cfg.get("mode") == "report":
                new_text = text  # observe only: log it, change nothing
            else:
                new_text = sanitizer.envelope(clean_text, verdict, removed)

            cfg_mod.record(tool_name, verdict, action)
            logger.warning(
                "injection-guard: %s result flagged (score=%s signals=%s action=%s)",
                tool_name, verdict.score, verdict.families(), action,
            )

            if setter is not None:
                setter(new_text)
                return result
            return new_text

        except Exception as exc:  # never let the guard break a tool call
            logger.debug("injection-guard skipped %s: %s", tool_name, exc)
            return result

    return on_tool_execution


def _stats_tool(**_kwargs):
    import json

    cfg_mod = _mod("settings")

    return json.dumps(cfg_mod.stats(), indent=2)


def _guard_command(raw_args: str = "") -> str:
    cfg_mod = _mod("settings")

    info = cfg_mod.stats()
    lines = [
        f"injection-guard — mode: {info['mode']} · threshold: {info['threshold']}",
        f"blocked this session: {info['blocked_total']}",
    ]
    if info["by_signal"]:
        lines.append("signals: " + ", ".join(f"{k}×{v}" for k, v in sorted(info["by_signal"].items())))
    if info["by_tool"]:
        lines.append("tools: " + ", ".join(f"{k}×{v}" for k, v in sorted(info["by_tool"].items())))
    lines.append(f"audit: {info['audit_path']}")
    for entry in info["recent"]:
        lines.append(f"  {entry['ts']}  {entry['tool']}  score={entry['score']}  {','.join(entry['signals'])}")
    return "\n".join(lines)


def register(ctx) -> None:
    """Wire the middleware, a read-only report tool, and the /guard command."""
    ctx.register_middleware("tool_execution", make_middleware(ctx))

    ctx.register_tool(
        name="injection_guard_stats",
        toolset=_TOOLSET,
        schema={
            "name": "injection_guard_stats",
            "description": (
                "Report what the prompt-injection guard has blocked: mode, threshold, "
                "counts by tool and by signal family, and the last few audit entries. "
                "Read-only; it never returns the offending text."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
        handler=_stats_tool,
        description="Show prompt-injection blocks and guard settings",
        emoji="🛡️",
    )

    ctx.register_command(
        "guard",
        _guard_command,
        description="Show injection-guard status and recent blocks",
    )

    logger.debug("injection-guard registered")
