"""Unit and integration tests for global Claude Code + Antigravity hooks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent.parent / "hooks"


def run_claude_hook(
    script_name: str,
    tool_name: str,
    tool_input: dict,
    *,
    event: str = "PreToolUse",
    cwd: str | None = None,
) -> tuple[int, dict, str]:
    payload = {
        "hook_event_name": event,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "cwd": cwd or os.getcwd(),
    }
    return _exec_hook(script_name, payload)


def run_agy_hook(
    script_name: str,
    tool_name: str,
    args: dict,
    *,
    event: str = "PreToolUse",
    cwd: str | None = None,
) -> tuple[int, dict, str]:
    payload = {
        "hookEventName": event,
        "toolCall": {
            "id": "toolu_test",
            "name": tool_name,
            "args": args,
        },
        "cwd": cwd or os.getcwd(),
    }
    return _exec_hook(script_name, payload)


def _exec_hook(script_name: str, payload: dict) -> tuple[int, dict, str]:
    script = HOOKS_DIR / script_name
    proc = subprocess.run(
        [sys.executable, str(script)],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        timeout=10,
    )
    stdout = proc.stdout.strip()
    data = json.loads(stdout) if stdout else {}
    return proc.returncode, data, proc.stderr


def claude_decision(data: dict) -> str:
    return data.get("hookSpecificOutput", {}).get("permissionDecision", "allow")


class TestProtectFilesystem(unittest.TestCase):
    def test_denies_rm_rf_root(self) -> None:
        rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": "rm -rf /"})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "deny")

    def test_denies_sudo_rm_rf_etc(self) -> None:
        rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": "sudo rm -rf /etc"})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "deny")

    def test_denies_rm_rf_home_tilde_and_var(self) -> None:
        for cmd in ("rm -rf ~", "rm -rf ~/*", "rm -rf $HOME", "rm -rf ${HOME}/"):
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_denies_rm_rf_unresolved_variable(self) -> None:
        rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": 'rm -rf "$TARGET_DIR"'})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "deny")

    def test_denies_rm_rf_via_nested_bash_c(self) -> None:
        rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": 'bash -c "rm -rf /usr"'})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "deny")

    def test_denies_windows_drive_root_and_dd_device(self) -> None:
        for cmd in ("rm -rf C:/", "dd if=/dev/zero of=/dev/sda bs=1M", "mkfs.ext4 /dev/nvme0n1"):
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_denies_symlink_to_protected_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "sneaky"
            link.symlink_to("/etc")
            rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": f"rm -rf {link}"}, cwd=tmp)
            self.assertEqual(rc, 0)
            self.assertEqual(claude_decision(data), "deny")

    def test_denies_find_delete_on_root(self) -> None:
        rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": "find / -name '*.tmp' -delete"})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "deny")

    def test_asks_recursive_delete_outside_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            target = Path(tmp2) / "subdir"
            target.mkdir()
            # Use a non-/tmp path simulation by testing rm -rf . inside cwd
            rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": "rm -rf ."}, cwd=tmp1)
            self.assertEqual(rc, 0)
            self.assertEqual(claude_decision(data), "ask")

    def test_allows_safe_local_and_tmp_deletes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for cmd in ("rm foo.txt", "rm -rf ./dist", "rm -rf node_modules", f"rm -rf {tmp}/cache", "ls -la /"):
                with self.subTest(cmd=cmd):
                    rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": cmd}, cwd=tmp)
                    self.assertEqual(rc, 0)
                    self.assertEqual(claude_decision(data), "allow")

    def test_allows_harmless_dev_targets(self) -> None:
        for cmd in ("dd if=big.bin of=/dev/null bs=1M", "rm /dev/shm/test.sock"):
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "allow")

    def test_still_denies_dev_shm_itself_and_other_devices(self) -> None:
        for cmd in ("rm -rf /dev/shm", "rm /dev/sda", "dd if=/dev/zero of=/dev/shm/../sda"):
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_allows_commit_message_heredoc_that_mentions_a_deletion(self) -> None:
        cmd = "git commit -q -F - <<'EOF'\nfix: guard root\n\nrm -rf / is now denied\nEOF"
        rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": cmd})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "allow")

    def test_denies_deletions_in_code_heredocs_and_after_a_commit_heredoc(self) -> None:
        cmds = (
            "bash <<'EOF'\nrm -rf /\nEOF",
            "cat <<'EOF' | sh\nrm -rf /\nEOF",
            "git commit -F - <<'EOF'\nfix: note\nEOF\nrm -rf /",
            "git commit -F - <<'EOF' && rm -rf /\nfix: note\nEOF",
        )
        for cmd in cmds:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-filesystem.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_antigravity_protocol_denies_root_rm(self) -> None:
        rc, data, _ = run_agy_hook("protect-filesystem.py", "run_command", {"CommandLine": "rm -rf /"})
        self.assertEqual(rc, 0)
        self.assertEqual(data.get("decision"), "deny")
        self.assertTrue(data.get("reason"))


class TestProtectSecrets(unittest.TestCase):
    def test_denies_reading_protected_secret_files_claude_and_agy(self) -> None:
        secret_paths = [
            "/project/.env",
            "/project/.env.production",
            str(Path.home() / ".ssh" / "id_ed25519"),
            str(Path.home() / ".aws" / "credentials"),
            str(Path.home() / ".npmrc"),
            str(Path.home() / ".claude" / ".credentials.json"),
            str(Path.home() / ".pi" / "agent" / "auth.json"),
            "/project/certs/server.pem",
            "/project/certs/private.key",
        ]
        for path in secret_paths:
            with self.subTest(path=path):
                rc, data, _ = run_claude_hook("protect-secrets.py", "Read", {"file_path": path})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

                rc2, data2, _ = run_agy_hook("protect-secrets.py", "read_file", {"Path": path})
                self.assertEqual(rc2, 0)
                self.assertEqual(data2.get("decision"), "deny")

    def test_denies_shell_access_to_secret_files(self) -> None:
        for cmd in ("cat .env", "head -n 5 ~/.aws/credentials", "grep KEY .env.local", "cat ~/.ssh/id_rsa"):
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-secrets.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_allows_safe_template_and_public_files(self) -> None:
        safe_paths = [
            "/project/.env.example",
            "/project/.env.sample",
            "/project/.env.template",
            str(Path.home() / ".ssh" / "id_ed25519.pub"),
            "/project/package.json",
            "/project/src/config.py",
        ]
        for path in safe_paths:
            with self.subTest(path=path):
                rc, data, _ = run_claude_hook("protect-secrets.py", "Read", {"file_path": path})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "allow")

    def test_allows_jq_field_expression_ending_in_key(self) -> None:
        rc, data, _ = run_claude_hook("protect-secrets.py", "Bash", {"command": "jq .foo.key config.json"})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "allow")

    def test_denies_symlink_to_env_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret = Path(tmp) / ".env"
            secret.write_text("SECRET=123\n", encoding="utf-8")
            link = Path(tmp) / "notes.txt"
            link.symlink_to(secret)
            rc, data, _ = run_claude_hook("protect-secrets.py", "Read", {"file_path": str(link)}, cwd=tmp)
            self.assertEqual(rc, 0)
            self.assertEqual(claude_decision(data), "deny")

    def test_allows_shell_commands_that_name_a_secret_without_reading_it(self) -> None:
        cmds = (
            "grep -c id_rsa README.md",
            "rg -n id_ed25519 docs",
            "git check-ignore .env",
            "ls -la ~/.gnupg",
            "[ -f .env ]",
            "stat .env",
        )
        with tempfile.TemporaryDirectory() as tmp:
            for cmd in cmds:
                with self.subTest(cmd=cmd):
                    rc, data, _ = run_claude_hook("protect-secrets.py", "Bash", {"command": cmd}, cwd=tmp)
                    self.assertEqual(rc, 0)
                    self.assertEqual(claude_decision(data), "allow")

    def test_denies_grep_on_secret_file_however_the_pattern_is_given(self) -> None:
        cmds = (
            "grep -e KEY .env",
            "grep -eKEY .env",
            "grep --regexp=KEY .env",
            "grep -f patterns.txt .env",
            "grep --file=patterns.txt .env",
            "rg KEY .env",
            "ls . && cat .env",
        )
        for cmd in cmds:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-secrets.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_allows_creating_env_from_template_only_when_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".env.example").write_text("KEY=\n", encoding="utf-8")
            cmd = {"command": "cp .env.example .env"}
            rc, data, _ = run_claude_hook("protect-secrets.py", "Bash", cmd, cwd=tmp)
            self.assertEqual(rc, 0)
            self.assertEqual(claude_decision(data), "allow")

            (Path(tmp) / ".env").write_text("KEY=real\n", encoding="utf-8")
            for command in ("cp .env.example .env", "cp .env backup.txt", "cp -t out .env.example .env"):
                with self.subTest(command=command):
                    rc, data, _ = run_claude_hook("protect-secrets.py", "Bash", {"command": command}, cwd=tmp)
                    self.assertEqual(rc, 0)
                    self.assertEqual(claude_decision(data), "deny")

    def test_allows_commit_messages_that_mention_secret_files(self) -> None:
        cmds = (
            'git commit -m "docs: document config/.env"',
            'git commit -am "docs: document config/.env"',
            'git commit "--message=docs: document config/.env"',
            "git commit -q -F - <<'EOF'\ndocs: setup\n\ncopy the template, then edit .env\nEOF",
            "cd repo && git commit -F - <<EOF\ncat .env is blocked by the hook\nEOF\ngit log -1",
        )
        for cmd in cmds:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-secrets.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "allow")

    def test_denies_secret_reads_around_commit_messages_and_heredocs(self) -> None:
        cmds = (
            "git commit -F .env",
            'git commit -m "docs: note" && cat .env',
            "git commit -F - <<'EOF'\ndocs: note\nEOF\ncat .env",
            "git commit -F - <<'EOF' && cat .env\ndocs: note\nEOF",
            "bash <<'EOF'\ncat .env\nEOF",
            "cat <<'EOF' | sh\ncat .env\nEOF",
        )
        for cmd in cmds:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-secrets.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_pem_is_denied_only_when_it_may_hold_a_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cert = Path(tmp) / "ca.pem"
            cert.write_text("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n", encoding="utf-8")
            key = Path(tmp) / "server.pem"
            key.write_text("-----BEGIN " + "PRIVATE KEY-----\nabc\n", encoding="utf-8")
            cases = ((cert, "allow"), (key, "deny"), (Path(tmp) / "missing.pem", "deny"))
            for path, expected in cases:
                with self.subTest(path=path.name):
                    rc, data, _ = run_claude_hook("protect-secrets.py", "Read", {"file_path": str(path)})
                    self.assertEqual(rc, 0)
                    self.assertEqual(claude_decision(data), expected)

            rc, data, _ = run_claude_hook(
                "protect-secrets.py", "Bash", {"command": "openssl x509 -in ca.pem -noout -text"}, cwd=tmp
            )
            self.assertEqual(rc, 0)
            self.assertEqual(claude_decision(data), "allow")

    def test_project_npmrc_is_denied_only_when_it_may_hold_a_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plain = Path(tmp) / ".npmrc"
            plain.write_text(
                "registry=https://registry.npmjs.org/\n//npm.pkg.github.com/:_authToken=${NPM_TOKEN}\n",
                encoding="utf-8",
            )
            (Path(tmp) / "sub").mkdir()
            with_token = Path(tmp) / "sub" / ".npmrc"
            with_token.write_text("//registry.npmjs.org/:_auth" + "Token=npm_abc123\n", encoding="utf-8")
            cases = ((plain, "allow"), (with_token, "deny"), (Path(tmp) / "missing" / ".npmrc", "deny"))
            for path, expected in cases:
                with self.subTest(path=str(path.relative_to(tmp))):
                    rc, data, _ = run_claude_hook("protect-secrets.py", "Read", {"file_path": str(path)})
                    self.assertEqual(rc, 0)
                    self.assertEqual(claude_decision(data), expected)

    def test_secret_json_matches_credential_names_not_any_word(self) -> None:
        cases = (
            ("/project/locales/secret-santa.json", "allow"),
            ("/project/secrets.json", "deny"),
            ("/project/app-secrets.json", "deny"),
            ("/project/client_secret_123.json", "deny"),
            ("/project/service-account-prod.json", "deny"),
        )
        for path, expected in cases:
            with self.subTest(path=path):
                rc, data, _ = run_claude_hook("protect-secrets.py", "Read", {"file_path": path})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), expected)


if __name__ == "__main__":
    unittest.main()
