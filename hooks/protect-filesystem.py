#!/usr/bin/env python3
"""PreToolUse hook: block dangerous deletion commands and protected filesystem targets."""

from __future__ import annotations

import os
import re
from pathlib import Path

from _hook_common import emit_pre, get_command, read_event, split_shell_segments

DELETE_BINS = {"rm", "rmdir", "unlink", "shred"}
DISK_WIPE_BINS = {"mkfs", "wipefs", "fdisk", "parted", "sfdisk"}
CRITICAL_PREFIXES = (
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/proc",
    "/root",
    "/sbin",
    "/sys",
    "/usr",
    "/System",
    "/Library",
    "/Applications",
)
PROTECTED_EXACT = {
    "/",
    "/home",
    "/media",
    "/mnt",
    "/opt",
    "/run",
    "/srv",
    "/tmp",
    "/var",
    "/var/tmp",
    "/Users",
}
WINDOWS_PROTECTED_RE = re.compile(
    r"^[A-Za-z]:[/\\]?$|^[A-Za-z]:[/\\](windows|program files( \(x86\))?|users|system32)([/\\].*)?$",
    re.IGNORECASE,
)
HOME_VAR_RE = re.compile(r"^(\$HOME|\$\{HOME\}|~)(/(\*)?)?$")
UNRESOLVED_VAR_RE = re.compile(r"\$[A-Za-z_{}(]|`")


def _strip_glob_tail(path_str: str) -> str:
    cleaned = path_str.rstrip("/")
    if cleaned.endswith("/*"):
        cleaned = cleaned[:-2]
    return cleaned or "/"


def _is_protected_resolved(resolved: str, home_str: str) -> bool:
    norm = resolved.rstrip("/") or "/"
    if norm in PROTECTED_EXACT or norm == home_str:
        return True
    for prefix in CRITICAL_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return True
    return False


def _resolve_target(target: str, cwd: str) -> tuple[str, str]:
    expanded = os.path.expanduser(_strip_glob_tail(target))
    raw_path = Path(expanded) if os.path.isabs(expanded) else Path(cwd) / expanded
    norm_abs = os.path.normpath(str(raw_path))
    try:
        real_abs = os.path.realpath(str(raw_path))
    except OSError:
        real_abs = norm_abs
    return norm_abs, real_abs


def _check_rm_segment(tokens: list[str], cwd: str) -> tuple[str, str] | None:
    is_recursive = False
    targets: list[str] = []
    end_opts = False

    for tok in tokens[1:]:
        if not end_opts and tok == "--":
            end_opts = True
            continue
        if not end_opts and tok.startswith("-"):
            if tok == "--recursive" or (not tok.startswith("--") and ("r" in tok[1:] or "R" in tok[1:])):
                is_recursive = True
            continue
        targets.append(tok)

    home_str = str(Path.home()).rstrip("/")
    cwd_real = os.path.realpath(cwd).rstrip("/") or "/"
    ask_reason: str | None = None

    for target in targets:
        if WINDOWS_PROTECTED_RE.match(target):
            return ("deny", f"Blocked deletion targeting protected drive/system path: {target}")
        if HOME_VAR_RE.match(target):
            return ("deny", f"Blocked deletion targeting home directory: {target}")
        if UNRESOLVED_VAR_RE.search(target):
            if is_recursive or target.startswith(("$HOME", "${HOME}")):
                return ("deny", f"Blocked destructive deletion with unverified variable/expansion: {target}")

        stripped = _strip_glob_tail(target)
        if stripped in ("..", "../.."):
            return ("deny", f"Blocked deletion targeting parent directory: {target}")

        norm_abs, real_abs = _resolve_target(target, cwd)
        if _is_protected_resolved(norm_abs, home_str) or _is_protected_resolved(real_abs, home_str):
            return ("deny", f"Blocked deletion targeting protected system/root path: {target}")

        if is_recursive:
            if target in (".", "./", "*", "./*"):
                ask_reason = f"Recursive deletion of entire current directory ({target}) requires explicit approval."
            elif (
                not real_abs.startswith(cwd_real + "/")
                and real_abs != cwd_real
                and not real_abs.startswith(("/tmp/", "/var/tmp/"))
            ):
                ask_reason = f"Recursive deletion outside current workspace ({target}) requires explicit approval."

    if ask_reason:
        return ("ask", ask_reason)
    return None


def _check_segment(tokens: list[str], cwd: str) -> tuple[str, str] | None:
    base = os.path.basename(tokens[0])
    home_str = str(Path.home()).rstrip("/")

    if base in DELETE_BINS:
        return _check_rm_segment(tokens, cwd)

    if base in DISK_WIPE_BINS or base.startswith("mkfs."):
        return ("deny", f"Blocked destructive disk/partition command: {base}")

    if base == "dd":
        for tok in tokens[1:]:
            if tok.startswith("of=/dev/"):
                return ("deny", f"Blocked raw device write via dd: {tok}")

    if base == "find":
        has_delete = "-delete" in tokens or (
            "-exec" in tokens and any(os.path.basename(t) in DELETE_BINS for t in tokens)
        )
        if has_delete:
            roots = [t for t in tokens[1:] if not t.startswith("-") and t not in (";", "+")]
            search_root = roots[0] if roots else "."
            norm_abs, real_abs = _resolve_target(search_root, cwd)
            if _is_protected_resolved(norm_abs, home_str) or _is_protected_resolved(real_abs, home_str):
                return ("deny", f"Blocked recursive find deletion on protected path: {search_root}")

    if base in ("chmod", "chown"):
        recursive = any(t == "--recursive" or (t.startswith("-") and not t.startswith("--") and "R" in t) for t in tokens[1:])
        if recursive:
            for tok in tokens[2:]:
                if tok.startswith("-"):
                    continue
                norm_abs, real_abs = _resolve_target(tok, cwd)
                if _is_protected_resolved(norm_abs, home_str) or _is_protected_resolved(real_abs, home_str):
                    return ("deny", f"Blocked recursive {base} on protected path: {tok}")

    return None


def main() -> None:
    event = read_event()
    if not event:
        return
    cmd = get_command(event)
    if not cmd:
        emit_pre(event.agent, "allow")
        return

    ask_result: tuple[str, str] | None = None
    for seg in split_shell_segments(cmd):
        verdict = _check_segment(seg, event.cwd)
        if verdict is None:
            continue
        if verdict[0] == "deny":
            emit_pre(event.agent, "deny", verdict[1])
            return
        ask_result = verdict

    if ask_result:
        emit_pre(event.agent, ask_result[0], ask_result[1])
    else:
        emit_pre(event.agent, "allow")


if __name__ == "__main__":
    main()
