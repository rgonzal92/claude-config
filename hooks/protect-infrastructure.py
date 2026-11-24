#!/usr/bin/env python3
"""PreToolUse hook: require approval for deployments and infrastructure modifications."""

from __future__ import annotations

import os

from _hook_common import emit_pre, get_command, read_event, split_shell_segments

TF_BINS = {"terraform", "tofu", "terragrunt"}
TF_MUTATE = {"apply", "destroy", "import", "taint", "untaint", "force-unlock"}
TF_STATE_MUTATE = {"rm", "mv", "push", "replace-provider"}
KUBECTL_MUTATE = {
    "apply",
    "delete",
    "create",
    "replace",
    "patch",
    "edit",
    "scale",
    "autoscale",
    "rollout",
    "drain",
    "cordon",
    "uncordon",
    "taint",
    "exec",
    "cp",
    "set",
    "label",
    "annotate",
    "expose",
    "run",
}
KUBECTL_VAL_FLAGS = {"-n", "--namespace", "--context", "--kubeconfig", "-l", "--selector"}
HELM_MUTATE = {"install", "upgrade", "uninstall", "delete", "rollback", "push"}
AWS_VAL_FLAGS = {"--profile", "--region", "--output", "--endpoint-url", "--color"}
AWS_READONLY_PREFIXES = (
    "get-",
    "list-",
    "describe-",
    "head-",
    "filter-",
    "select-",
    "show-",
    "check-",
    "validate-",
    "lookup-",
)
AWS_MUTATE_PREFIXES = (
    "create-",
    "delete-",
    "put-",
    "update-",
    "modify-",
    "terminate-",
    "stop-",
    "start-",
    "reboot-",
    "deploy",
    "invoke",
    "publish",
    "remove-",
    "deregister-",
    "register-",
    "attach-",
    "detach-",
    "associate-",
    "disassociate-",
    "enable-",
    "disable-",
    "import-",
    "restore-",
    "reset-",
    "purge-",
    "revoke-",
    "authorize-",
    "run-",
    "send-",
    "tag-",
    "untag-",
    "set-",
    "cancel-",
    "execute-",
)
CLOUD_MUTATE_VERBS = {
    "deploy",
    "create",
    "delete",
    "update",
    "destroy",
    "remove",
    "apply",
    "patch",
    "stop",
    "start",
    "reset",
    "restart",
    "set",
    "import",
}
SYSTEMCTL_MUTATE = {"start", "stop", "restart", "reload", "enable", "disable", "mask", "unmask"}


def _positional(tokens: list[str], value_flags: set[str] | None = None) -> list[str]:
    vflags = value_flags or set()
    pos: list[str] = []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in vflags:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        pos.append(tok)
        i += 1
    return pos


def _check_segment(tokens: list[str]) -> str | None:
    base = os.path.basename(tokens[0])
    rest = tokens[1:]

    if base in TF_BINS:
        pos = _positional(tokens)
        if not pos:
            return None
        if pos[0] in TF_MUTATE:
            return f"Infrastructure mutation (`{base} {pos[0]}`) requires explicit user approval."
        if pos[0] == "state" and len(pos) > 1 and pos[1] in TF_STATE_MUTATE:
            return f"Terraform state mutation (`{base} state {pos[1]}`) requires explicit user approval."
        return None

    if base == "pulumi":
        pos = _positional(tokens)
        if pos and pos[0] in {"up", "destroy", "refresh", "import", "state"}:
            return f"Infrastructure operation (`pulumi {pos[0]}`) requires explicit user approval."
        return None

    if base == "kubectl":
        pos = _positional(tokens, KUBECTL_VAL_FLAGS)
        if pos and pos[0] in KUBECTL_MUTATE:
            return f"Kubernetes mutation (`kubectl {pos[0]}`) requires explicit user approval."
        return None

    if base == "helm":
        pos = _positional(tokens, {"-n", "--namespace", "--kube-context"})
        if pos and pos[0] in HELM_MUTATE:
            return f"Helm deployment operation (`helm {pos[0]}`) requires explicit user approval."
        return None

    if base == "aws":
        pos = _positional(tokens, AWS_VAL_FLAGS)
        if len(pos) < 2:
            return None
        service, action = pos[0], pos[1]
        if service == "s3":
            if action in {"rm", "rb", "mb", "mv"}:
                return f"AWS S3 mutation (`aws s3 {action}`) requires explicit user approval."
            if action in {"cp", "sync"} and len(pos) >= 4 and pos[3].startswith("s3://"):
                return f"AWS S3 upload (`aws s3 {action}` to S3) requires explicit user approval."
            return None
        if action.startswith(AWS_READONLY_PREFIXES) or action in {"scan", "query", "wait"}:
            return None
        if action.startswith(AWS_MUTATE_PREFIXES):
            return f"AWS mutation (`aws {service} {action}`) requires explicit user approval."
        return None

    if base in {"gcloud", "az"}:
        pos = _positional(tokens)
        if pos and pos[0] not in {"config", "auth", "version", "info", "account"}:
            if any(p in CLOUD_MUTATE_VERBS for p in pos[1:]):
                return f"Cloud infrastructure mutation (`{base} {' '.join(pos[:3])}`) requires explicit user approval."
        return None

    if base == "wrangler":
        pos = _positional(tokens)
        if pos and (pos[0] in {"deploy", "publish", "delete", "secret"} or (pos[0] == "d1" and "execute" in pos)):
            return f"Cloudflare deployment/mutation (`wrangler {pos[0]}`) requires explicit user approval."
        return None

    if base == "vercel":
        if "--prod" in rest or any(t in {"deploy", "rm", "remove", "env"} for t in rest):
            return "Vercel deployment/configuration change requires explicit user approval."
        return None

    if base == "netlify":
        pos = _positional(tokens)
        if pos and pos[0] in {"deploy", "env:set", "env:unset"}:
            return f"Netlify deployment/mutation (`netlify {pos[0]}`) requires explicit user approval."
        return None

    if base in {"fly", "flyctl"}:
        pos = _positional(tokens)
        if pos and pos[0] in {"deploy", "destroy", "secrets", "scale", "machines"}:
            return f"Fly.io deployment/mutation (`{base} {pos[0]}`) requires explicit user approval."
        return None

    if base in {"serverless", "sls", "cdk"}:
        pos = _positional(tokens)
        if pos and pos[0] in {"deploy", "destroy", "remove", "bootstrap"}:
            return f"Deployment command (`{base} {pos[0]}`) requires explicit user approval."
        return None

    if base == "ansible-playbook":
        return "Running `ansible-playbook` requires explicit user approval."

    if base == "docker":
        pos = _positional(tokens)
        if pos and pos[0] in {"push", "stack", "swarm"}:
            return f"Docker publish/cluster operation (`docker {pos[0]}`) requires explicit user approval."
        return None

    if base == "gh" and len(tokens) >= 3 and tokens[1] == "workflow" and tokens[2] == "run":
        return "Triggering a GitHub Actions workflow (`gh workflow run`) requires explicit user approval."

    if base == "systemctl":
        pos = _positional(tokens)
        if pos and pos[0] in SYSTEMCTL_MUTATE:
            return f"System service modification (`systemctl {pos[0]}`) requires explicit user approval."
        return None

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
        reason = _check_segment(seg)
        if reason:
            emit_pre(event.agent, "ask", reason)
            return

    emit_pre(event.agent, "allow")


if __name__ == "__main__":
    main()
