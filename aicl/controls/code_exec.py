"""C-CODE-EXEC: Malicious code execution prevention (R2, P0). Threat TH-15.

Contract notes (ARCHITECTURE.md §4.1, §6.3, §7):
- Stages: tool_call, output
- Priority: 35 (deterministic check)
- Purpose: Prevent shell injection, command chaining, reverse shells, eval/exec abuse.
- Scans output segments and tool_call arguments.
"""

from __future__ import annotations

import json
import re
from typing import Any

from aicl import feeds
from aicl.models import Action, Decision, Match, RequestContext, Stage
from aicl.registry import register_control

_DEFAULT_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "shell_metachar_chain": [
        re.compile(
            r"(?:^|[;&|\n`$])\s*(?:rm\s+-[rf]{1,2}|sh\s+-c|bash\s+-c|cat\s+/etc/shadow|cat\s+/etc/passwd|chmod\s+[0-7]{3,4})\b",
            re.IGNORECASE,
        ),
        re.compile(r"[;&|`]\s*(?:/bin/)?(?:bash|sh|zsh|dash)\b", re.IGNORECASE),
        re.compile(r"\$\((?:/bin/)?(?:bash|sh|curl|wget|nc|python)\b", re.IGNORECASE),
        re.compile(r";\s*(?:rm|reboot|shutdown|mkfs|dd\s+if=)\b", re.IGNORECASE),
    ],
    "eval_exec": [
        re.compile(
            r"\b(?:eval|exec)\s*\([^)]*?\b(?:__import__|os\.|subprocess\.|open\s*\(|compile\s*\()",
            re.IGNORECASE,
        ),
        re.compile(r"\b__import__\s*\(\s*['\"](?:os|subprocess|pty|socket)['\"]\s*\)", re.IGNORECASE),
        re.compile(r"\bgetattr\s*\(\s*__builtins__\s*,\s*['\"](?:eval|exec)['\"]\s*\)", re.IGNORECASE),
        re.compile(r"\bcompile\s*\(.*?['\"](?:exec|eval)['\"]\s*\)", re.IGNORECASE),
    ],
    "curl_pipe_sh": [
        re.compile(r"\bcurl\s+[^|\n]+?\|\s*(?:/bin/)?(?:ba|z|da)?sh\b", re.IGNORECASE),
        re.compile(r"\bwget\s+[^|\n]+?\|\s*(?:/bin/)?(?:ba|z|da)?sh\b", re.IGNORECASE),
        re.compile(r"\bcurl\s+[^|\n]+?-[oO]\s+[^|\n]+?&&\s*(?:/bin/)?(?:ba|z|da)?sh\b", re.IGNORECASE),
        re.compile(r"\bcurl\s+[^|\n]+?\|\s*(?:/bin/)?python\b", re.IGNORECASE),
    ],
    "reverse_shell": [
        re.compile(r"(?:/bin/)?(?:ba|z)?sh\s+-i\s+>(?:&|/dev/tcp/)", re.IGNORECASE),
        re.compile(
            r"\b(?:nc|ncat|netcat)\s+(?:-e\s+|-c\s+|(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+[0-9]{2,5})",
            re.IGNORECASE,
        ),
        re.compile(r"/dev/tcp/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{2,5}", re.IGNORECASE),
        re.compile(r"\bsocket\.socket\b.*?\bconnect\s*\(.*?\bexec\b", re.IGNORECASE | re.DOTALL),
        re.compile(r"\bmkfifo\s+/tmp/.*?/bin/(?:ba)?sh", re.IGNORECASE),
    ],
}


def _cfg_val(cfg: Any, key: str, default: Any = None) -> Any:
    if hasattr(cfg, "get"):
        return cfg.get(key, default)
    return getattr(cfg, key, default) if hasattr(cfg, key) else default


@register_control
class CodeExecPatternsControl:
    id: str = "C-CODE-EXEC"
    stages: tuple[Stage, ...] = (Stage.tool_call, Stage.output)
    priority: int = 35  # < 100, cheap deterministic check

    async def evaluate(self, ctx: RequestContext, cfg: Any) -> Decision:
        target_action = Action(_cfg_val(cfg, "action", Action.block))
        threat_ids = list(_cfg_val(cfg, "threat_ids", ["TH-15"]))
        configured_patterns = _cfg_val(
            cfg, "patterns", ["shell_metachar_chain", "eval_exec", "curl_pipe_sh", "reverse_shell"]
        )
        if isinstance(configured_patterns, str):
            configured_patterns = [configured_patterns]

        active_regexes: list[tuple[str, re.Pattern[str]]] = []
        for name in configured_patterns:
            if name in _DEFAULT_PATTERNS:
                for rx in _DEFAULT_PATTERNS[name]:
                    active_regexes.append((name, rx))

        # Also load from feed if code_exec set has signatures
        snap = feeds.current()
        for sig in snap.for_set("code_exec"):
            rx = snap.regex(sig.id)
            if rx is not None:
                active_regexes.append((sig.id, rx))

        matches: list[Match] = []

        # Texts to inspect
        targets: list[tuple[int | None, str, bool]] = []  # (segment_idx, text, in_decoded)

        # Output stage: inspect assistant output segments
        if ctx.stage == Stage.output:
            for seg in ctx.segments:
                targets.append((seg.idx, seg.text, False))
                for dec in seg.decoded:
                    targets.append((seg.idx, dec, True))

        # Tool_call stage: inspect tool arguments and any segments
        elif ctx.stage == Stage.tool_call:
            for seg in ctx.segments:
                targets.append((seg.idx, seg.text, False))
                for dec in seg.decoded:
                    targets.append((seg.idx, dec, True))

            if ctx.tool_args:
                args_str = json.dumps(ctx.tool_args, default=str)
                targets.append((None, args_str, False))

        for seg_idx, text, in_dec in targets:
            for kind, rx in active_regexes:
                m = rx.search(text)
                if m:
                    matches.append(
                        Match(
                            kind=kind,
                            segment_idx=seg_idx,
                            masked=f"[{kind}]",
                            in_decoded=in_dec,
                        )
                    )

        if matches:
            return Decision(
                control_id=self.id,
                threat_ids=threat_ids,
                action=target_action,
                severity="critical",
                reason=f"malicious code execution pattern detected: {matches[0].kind}",
                matches=matches,
            )

        return Decision(
            control_id=self.id,
            threat_ids=threat_ids,
            action=Action.allow,
            severity="low",
            reason="no code execution patterns detected",
        )
