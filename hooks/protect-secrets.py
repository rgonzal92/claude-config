#!/usr/bin/env python3
"""PreToolUse hook: block access to protected credentials and sensitive secret files."""

from __future__ import annotations

import os
import re
from pathlib import Path

from _hook_common import emit_pre, get_command, get_file_paths, git_subcommand, read_event, split_shell_segments

SAFE_ENV_NAMES = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.schema",
}
PROTECTED_BASENAMES = {
    ".netrc",
    ".pypirc",
    ".credentials.json",
    "credentials.json",
    "credentials.tfrc.json",
    "secrets.yaml",
    "secrets.yml",
    ".secrets",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
}
PROTECTED_EXTS = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx"}
SECRET_JSON_RE = re.compile(
    r"^(service[-_]?account.*|client[-_]?secret.*|(.*[-_.])?secrets?)\.json$", re.IGNORECASE
)
PRIVATE_KEY_RE = re.compile(rb"PRIVATE KEY")
# A credential line whose value is written out rather than read from `${ENV_VAR}`.
NPMRC_CREDENTIAL_RE = re.compile(rb"(?m)^[^#;\n]*(_auth|_authToken|_password)\s*=\s*(?!\$\{)\S")
MAX_INSPECT_BYTES = 1024 * 1024
NAME_ONLY_BINS = {"ls", "stat", "test", "["}  # report names and metadata, never contents
GIT_NAME_ONLY_SUBS = {"check-ignore", "ls-files"}
GREP_BINS = {"grep", "egrep", "fgrep", "rg"}
# `--regexp=PAT`, `--file=F`, `-ePAT`, `-fF`: the pattern is not the first positional argument.
GREP_INLINE_PATTERN_RE = re.compile(r"--(regexp|file)=|-[^-]*[ef].")
# A heredoc fed straight to `git commit` is message text. Only that case is dropped: a heredoc
# given to a shell, or piped onward, is code and stays checked.
COMMIT_HEREDOC_RE = re.compile(
    r"(\bgit\b[^\n|;&]*\bcommit\b[^\n|;&]*<<-?\s*(['\"]?)(\w+)\2[^\n|]*)\n.*?\n[ \t]*\3[ \t]*(?=\n|$)",
    re.DOTALL,
)
HOME_PROTECTED_REL = (
    ".npmrc",
    ".aws/credentials",
    ".kube/config",
    ".docker/config.json",
    ".config/gh/hosts.yml",
    ".config/glab-cli/config.yml",
    ".pi/agent/auth.json",
    ".claude/.credentials.json",
    ".terraform.d/credentials.tfrc.json",
)
HOME_PROTECTED_DIRS = (".gnupg",)


def _may_contain(path: str, pattern: re.Pattern[bytes]) -> bool:
    """True when the file matches, or cannot be inspected (fail closed)."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > MAX_INSPECT_BYTES:
            return True
        with open(path, "rb") as f:
            return bool(pattern.search(f.read()))
    except OSError:
        return True


def _check_single_path(path_str: str, home_str: str) -> str | None:
    norm = os.path.normpath(path_str)
    base = os.path.basename(norm)
    lower_base = base.lower()

    if lower_base in SAFE_ENV_NAMES or lower_base.endswith(".pub"):
        return None

    if lower_base == ".env" or lower_base.startswith(".env."):
        return f"Protected environment file: {base}"

    if lower_base in PROTECTED_BASENAMES:
        return f"Protected credential/secret file: {base}"

    # A project .npmrc usually holds registry settings only; ~/.npmrc is always protected below.
    if lower_base == ".npmrc" and _may_contain(norm, NPMRC_CREDENTIAL_RE):
        return f"Protected credential/secret file: {base}"

    _, ext = os.path.splitext(lower_base)
    if ext in PROTECTED_EXTS and not lower_base.startswith("."):
        # .pem is also the usual extension for public certificates.
        if ext != ".pem" or _may_contain(norm, PRIVATE_KEY_RE):
            return f"Protected key/certificate file: {base}"

    if SECRET_JSON_RE.match(base):
        return f"Protected secret JSON file: {base}"

    if norm.startswith(home_str + "/.ssh/") and lower_base.startswith("id_"):
        return f"Protected SSH private key: {base}"

    for rel in HOME_PROTECTED_REL:
        if norm == os.path.join(home_str, rel):
            return f"Protected credential store: ~/{rel}"

    for rel_dir in HOME_PROTECTED_DIRS:
        target_dir = os.path.join(home_str, rel_dir)
        if norm == target_dir or norm.startswith(target_dir + "/"):
            return f"Protected keystore directory: ~/{rel_dir}"

    return None


def check_path(raw_path: str, cwd: str) -> str | None:
    if not raw_path or raw_path.startswith(("http://", "https://")):
        return None
    home_str = str(Path.home()).rstrip("/")
    expanded = os.path.expanduser(raw_path)
    full = expanded if os.path.isabs(expanded) else os.path.join(cwd, expanded)

    reason = _check_single_path(full, home_str)
    if reason:
        return reason

    try:
        real = os.path.realpath(full)
    except OSError:
        return None
    if real != os.path.normpath(full):
        return _check_single_path(real, home_str)
    return None


def _without_commit_messages(args: list[str]) -> list[str]:
    """Drop `git commit` message text (-m, -am, --message): prose, not paths."""
    kept: list[str] = []
    skip_next = False
    for tok in args:
        if skip_next:
            skip_next = False
        elif tok == "--message" or (tok.startswith("-") and not tok.startswith("--") and tok.endswith("m")):
            skip_next = True
        elif not tok.startswith("--message="):
            kept.append(tok)
    return kept


def _readable_args(tokens: list[str], cwd: str) -> list[str]:
    """Arguments of one command that it could read as a file."""
    base = os.path.basename(tokens[0])
    args = tokens[1:]
    git_sub = git_subcommand(tokens)[0]
    if base in NAME_ONLY_BINS or git_sub in GIT_NAME_ONLY_SUBS:
        return []
    if git_sub == "commit":
        args = _without_commit_messages(args)
    positional = [t for t in args if not t.startswith("-")]
    if base in GREP_BINS:
        if positional and not any(GREP_INLINE_PATTERN_RE.match(t) for t in args):
            args.remove(positional[0])  # the search pattern
    elif base == "cp" and len(positional) == 2:
        source, dest = positional
        # shortcut: the destination is resolved against the hook cwd, so a preceding `cd` can hide
        # an existing .env from this check; track `cd` if that ever overwrites one.
        creates_from_template = os.path.basename(source).lower() in SAFE_ENV_NAMES and not os.path.lexists(
            os.path.join(cwd, os.path.expanduser(dest))
        )
        if creates_from_template:
            args.remove(dest)
    return args


def _candidate_tokens_from_shell(cmd: str, cwd: str) -> list[str]:
    candidates: list[str] = []
    cmd = COMMIT_HEREDOC_RE.sub(r"\1", cmd)
    for seg in split_shell_segments(cmd):
        for tok in _readable_args(seg, cwd):
            cleaned = tok.lstrip("<>@")
            if not cleaned:
                continue
            if "=" in cleaned and not cleaned.startswith(("/", ".", "~")):
                _, val = cleaned.split("=", 1)
                if val:
                    candidates.append(val.lstrip("@"))
            elif not cleaned.startswith("-"):
                candidates.append(cleaned)
    return candidates


def main() -> None:
    event = read_event()
    if not event:
        return

    for path in get_file_paths(event):
        reason = check_path(path, event.cwd)
        if reason:
            emit_pre(event.agent, "deny", f"Blocked access to sensitive file ({reason}).")
            return

    cmd = get_command(event)
    if cmd:
        for tok in _candidate_tokens_from_shell(cmd, event.cwd):
            reason = check_path(tok, event.cwd)
            if reason:
                emit_pre(event.agent, "deny", f"Blocked shell access to sensitive file ({reason}).")
                return

    emit_pre(event.agent, "allow")


if __name__ == "__main__":
    main()
