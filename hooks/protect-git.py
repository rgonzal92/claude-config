#!/usr/bin/env python3
"""PreToolUse hook: require approval for destructive or remote-mutating Git operations."""

from __future__ import annotations

import os

from _hook_common import emit_pre, get_command, git_subcommand, read_event, split_shell_segments


def _has_short_flag(tokens: list[str], char: str) -> bool:
    for tok in tokens:
        if tok == "--":
            break
        if tok.startswith("-") and not tok.startswith("--") and char in tok[1:]:
            return True
    return False


def _check_git(tokens: list[str]) -> str | None:
    sub, rest = git_subcommand(tokens)
    if not sub:
        return None

    if sub == "push":
        is_force = any(t in ("-f", "--force", "--force-with-lease") or t.startswith("--force-with-lease=") for t in rest)
        return "Git force push requires explicit user approval." if is_force else "Git push requires explicit user approval."

    if sub == "reset":
        if any(t in ("--hard", "--merge") for t in rest):
            return "Destructive `git reset` (--hard/--merge) requires explicit user approval."

    if sub == "checkout":
        if "--" in rest or "." in rest or any(t in ("-f", "--force") for t in rest):
            return "Discarding working tree changes via `git checkout` requires explicit user approval."

    if sub == "restore":
        staged_only = any(t in ("-S", "--staged") for t in rest) and not any(t in ("-W", "--worktree") for t in rest)
        if not staged_only:
            return "Discarding working tree changes via `git restore` requires explicit user approval."

    if sub == "clean":
        dry_run = "--dry-run" in rest or _has_short_flag(rest, "n")
        force = "--force" in rest or _has_short_flag(rest, "f")
        if force and not dry_run:
            return "Deleting untracked files via `git clean` requires explicit user approval."

    if sub == "rebase":
        return "Rewriting history via `git rebase` requires explicit user approval."

    if sub == "commit" and "--amend" in rest:
        return "Amending a commit via `git commit --amend` requires explicit user approval."

    if sub == "branch":
        if "-D" in rest or ("--delete" in rest and ("--force" in rest or "-f" in rest)):
            return "Force-deleting a branch (`git branch -D`) requires explicit user approval."

    if sub == "stash":
        action = next((t for t in rest if not t.startswith("-")), "push")
        if action not in ("list", "show"):
            return f"Modifying/stashing workspace changes (`git stash {action}`) requires explicit user approval."

    if sub in ("merge", "revert", "filter-branch", "filter-repo"):
        return f"Git `{sub}` operation requires explicit user approval."

    if sub == "reflog" and any(t in ("expire", "delete") for t in rest):
        return "Modifying git reflog requires explicit user approval."

    if sub == "gc" and any(t.startswith("--prune=now") for t in rest):
        return "Aggressive git garbage collection (`git gc --prune=now`) requires explicit user approval."

    return None


def _check_gh(tokens: list[str]) -> str | None:
    if len(tokens) < 3 or os.path.basename(tokens[0]) != "gh":
        return None
    pair = (tokens[1], tokens[2])
    if pair in {("release", "create"), ("release", "delete"), ("pr", "merge"), ("repo", "delete")}:
        return f"GitHub CLI operation (`gh {pair[0]} {pair[1]}`) requires explicit user approval."
    return None


def main() -> None:
    event = read_event()
    if not event:
        return
    cmd = get_command(event)
    if not cmd:
        emit_pre(event.agent, "allow")
        return

    for seg in split_shell_segments(cmd):
        reason = _check_git(seg) or _check_gh(seg)
        if reason:
            emit_pre(event.agent, "ask", reason)
            return

    emit_pre(event.agent, "allow")


if __name__ == "__main__":
    main()
