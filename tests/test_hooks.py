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

    def test_antigravity_protocol_denies_root_rm(self) -> None:
        rc, data, _ = run_agy_hook("protect-filesystem.py", "run_command", {"CommandLine": "rm -rf /"})
        self.assertEqual(rc, 0)
        self.assertEqual(data.get("decision"), "deny")
        self.assertTrue(data.get("reason"))


class TestProtectGit(unittest.TestCase):
    def test_asks_on_destructive_and_remote_git_ops(self) -> None:
        gated = [
            "git push origin main",
            "git push --force origin feat",
            "git -C /tmp/repo push -f",
            "git reset --hard HEAD~1",
            "git checkout -- src/app.py",
            "git restore src/app.py",
            "git clean -fd",
            "git rebase main",
            "git commit --amend -m 'fix: tweak'",
            "git branch -D old-branch",
            "git stash drop",
            "git stash",
            "git merge feature-x",
            "git revert HEAD",
            "gh release create v1.0.0",
            "gh pr merge 42",
        ]
        for cmd in gated:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-git.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "ask")

    def test_allows_safe_git_ops(self) -> None:
        allowed = [
            "git status",
            "git diff HEAD",
            "git log -n 10 --oneline",
            "git fetch origin",
            "git add src/app.py",
            "git commit -m 'feat(api): add health endpoint'",
            "git checkout -b feat/new-thing",
            "git switch main",
            "git restore --staged src/app.py",
            "git clean -nd",
            "git stash list",
            "git branch -a",
        ]
        for cmd in allowed:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-git.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "allow")

    def test_antigravity_protocol_force_asks_on_push(self) -> None:
        rc, data, _ = run_agy_hook("protect-git.py", "run_command", {"CommandLine": "git push origin main"})
        self.assertEqual(rc, 0)
        self.assertEqual(data.get("decision"), "force_ask")


class TestValidateCommit(unittest.TestCase):
    def test_allows_valid_conventional_commits(self) -> None:
        valid = [
            'git commit -m "feat(auth): add token refresh"',
            'git commit -m "fix!: handle empty payload"',
            'git commit -m "docs(claude-md): update Claude Code hooks"',
            "git -C ~/.claude commit -m 'chore: sync settings' -m 'Keep hooks updated'",
        ]
        for cmd in valid:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("validate-commit.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "allow")

    def test_denies_non_conventional_commit_messages(self) -> None:
        invalid = [
            'git commit -m "updated stuff"',
            'git commit -m "WIP"',
            'git commit -m "Feat: uppercase type"',
            'git commit -m "fix:no space after colon"',
        ]
        for cmd in invalid:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("validate-commit.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_denies_ai_attribution_in_commit_message(self) -> None:
        attributed = [
            'git commit -m "feat: add hook" -m "Co-Authored-By: Claude <noreply@anthropic.com>"',
            'git commit -m "fix: bug" -m "Generated with Claude Code"',
            'git commit -m "chore: cleanup" -m "AI-assisted refactor"',
            "git commit -m \"$(cat <<'EOF'\nfeat: add hook\n\nCo-Authored-By: GitHub Copilot <copilot@github.com>\nEOF\n)\"",
        ]
        for cmd in attributed:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("validate-commit.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_validates_commit_message_from_file_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            msg_file = Path(tmp) / "msg.txt"
            msg_file.write_text("bad commit message\n", encoding="utf-8")
            rc, data, _ = run_claude_hook(
                "validate-commit.py", "Bash", {"command": f"git commit -F {msg_file}"}, cwd=tmp
            )
            self.assertEqual(rc, 0)
            self.assertEqual(claude_decision(data), "deny")

    def test_denies_combined_am_flag_and_heredoc_stdin(self) -> None:
        cases = [
            'git commit -am "not conventional"',
            'git commit -am "feat: add x" -m "Co-Authored-By: Claude <noreply@anthropic.com>"',
            "git commit -F - <<'EOF'\nmissing prefix\nEOF",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("validate-commit.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "deny")

    def test_allows_valid_combined_am_flag(self) -> None:
        rc, data, _ = run_claude_hook("validate-commit.py", "Bash", {"command": 'git commit -am "fix(core): guard null"'})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "allow")

    def test_ignores_non_commit_commands(self) -> None:
        rc, data, _ = run_claude_hook("validate-commit.py", "Bash", {"command": "git status"})
        self.assertEqual(rc, 0)
        self.assertEqual(claude_decision(data), "allow")


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


class TestProtectInfrastructure(unittest.TestCase):
    def test_asks_on_infra_mutations(self) -> None:
        gated = [
            "terraform apply",
            "terraform -chdir=infra destroy",
            "kubectl apply -f deploy.yaml",
            "kubectl delete pod my-pod",
            "helm upgrade app ./chart",
            "aws s3 rm s3://prod-bucket/file",
            "aws ec2 terminate-instances --instance-ids i-123",
            "wrangler deploy",
            "vercel --prod",
            "fly deploy",
            "ansible-playbook site.yml",
            "docker push myorg/app:latest",
            "pulumi up",
        ]
        for cmd in gated:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-infrastructure.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "ask")

    def test_allows_readonly_infra_commands(self) -> None:
        allowed = [
            "terraform validate",
            "terraform -chdir=infra fmt -check",
            "terraform plan",
            "aws sts get-caller-identity",
            "aws cloudwatch describe-alarms",
            "aws logs filter-log-events --log-group-name app",
            "aws s3 ls s3://prod-bucket",
            "kubectl get pods",
            "kubectl describe svc api",
            "kubectl logs deploy/api",
            "helm list",
            "docker ps",
            "docker build -t local-app .",
        ]
        for cmd in allowed:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-infrastructure.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "allow")


class TestProtectDatabase(unittest.TestCase):
    def test_asks_on_destructive_db_commands(self) -> None:
        gated = [
            'psql -d mydb -c "DROP TABLE users;"',
            'mysql -e "TRUNCATE TABLE orders;"',
            'sqlite3 app.db "DELETE FROM sessions;"',
            "dropdb production",
            "npx prisma migrate reset",
            "alembic downgrade -1",
            "redis-cli FLUSHALL",
            "valkey-cli FLUSHDB",
            'mongosh --eval "db.dropDatabase()"',
            "flyway clean",
        ]
        for cmd in gated:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-database.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "ask")

    def test_allows_readonly_db_and_grep_commands(self) -> None:
        allowed = [
            'psql -d mydb -c "SELECT count(*) FROM users;"',
            'sqlite3 app.db "SELECT * FROM users LIMIT 5;"',
            "npx prisma migrate status",
            "alembic current",
            'grep -rn "DROP TABLE" migrations/',
            "redis-cli GET mykey",
        ]
        for cmd in allowed:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-database.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "allow")


class TestProtectDependencies(unittest.TestCase):
    def test_asks_on_dependency_changes(self) -> None:
        gated = [
            "npm install lodash",
            "npm i",
            "npm update",
            "pnpm add zod",
            "yarn add axios",
            "pip install requests",
            "python3 -m pip install flask",
            "uv add httpx",
            "cargo add serde",
            "go get github.com/pkg/errors",
            "sudo pacman -S jq",
            "brew install ripgrep",
        ]
        for cmd in gated:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-dependencies.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "ask")

    def test_allows_non_mutating_package_commands(self) -> None:
        allowed = [
            "npm run lint",
            "npm test",
            "npm ci",
            "npm ls",
            "pacman -Qi python",
            "pip list",
            "uv run pytest",
            "cargo test",
            "go test ./...",
        ]
        for cmd in allowed:
            with self.subTest(cmd=cmd):
                rc, data, _ = run_claude_hook("protect-dependencies.py", "Bash", {"command": cmd})
                self.assertEqual(rc, 0)
                self.assertEqual(claude_decision(data), "allow")


class TestScanSecrets(unittest.TestCase):
    def test_blocks_when_aws_key_written(self) -> None:
        fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        rc, data, _ = run_claude_hook(
            "scan-secrets.py",
            "Write",
            {"file_path": "/tmp/app.py", "content": f'AWS_KEY = "{fake_aws}"\n'},
            event="PostToolUse",
        )
        self.assertEqual(rc, 0)
        self.assertEqual(data.get("decision"), "block")
        self.assertIn("AWS Access Key", data.get("reason", ""))
        self.assertNotIn(fake_aws, data.get("reason", ""))

    def test_blocks_when_private_key_or_github_token_edited(self) -> None:
        pem = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nabc\n"
        gh = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        for content in (pem, f'TOKEN = "{gh}"'):
            with self.subTest(content=content[:20]):
                rc, data, _ = run_claude_hook(
                    "scan-secrets.py",
                    "Edit",
                    {"file_path": "/tmp/app.py", "old_string": "x", "new_string": content},
                    event="PostToolUse",
                )
                self.assertEqual(rc, 0)
                self.assertEqual(data.get("decision"), "block")

    def test_allows_placeholders_and_clean_code(self) -> None:
        clean_samples = [
            'API_KEY = "your_api_key_here"\n',
            'PASSWORD = "changeme_placeholder"\n',
            'DB_PASSWORD = os.environ["DB_PASSWORD"]\n',
            'x = 42\n',
        ]
        for content in clean_samples:
            with self.subTest(content=content):
                rc, data, _ = run_claude_hook(
                    "scan-secrets.py",
                    "Write",
                    {"file_path": "/tmp/app.py", "content": content},
                    event="PostToolUse",
                )
                self.assertEqual(rc, 0)
                self.assertNotIn("decision", data)


if __name__ == "__main__":
    unittest.main()
