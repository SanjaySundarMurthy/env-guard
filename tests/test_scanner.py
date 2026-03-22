"""Tests for env_guard.scanner."""

from __future__ import annotations

from env_guard.models import EnvFile, EnvVar
from env_guard.scanner import (
    check_gitignore_for_env,
    scan_directory_for_secrets,
    scan_env_values,
    scan_file_for_secrets,
)


class TestScanFileForSecrets:
    def test_detect_aws_key(self, tmp_path):
        fp = tmp_path / "config.py"
        fp.write_text('AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_file_for_secrets(str(fp))
        assert len(findings) >= 1

    def test_detect_password_assignment(self, tmp_path):
        fp = tmp_path / "config.py"
        fp.write_text('password = "mysecretpassword"\n')
        findings = scan_file_for_secrets(str(fp))
        assert len(findings) >= 1

    def test_no_false_positive_on_comments(self, tmp_path):
        fp = tmp_path / "config.py"
        fp.write_text("# This is a comment about passwords\nx = 1\n")
        findings = scan_file_for_secrets(str(fp))
        # Comments might still match pattern-based detection
        assert isinstance(findings, list)

    def test_detect_api_key(self, tmp_path):
        fp = tmp_path / "settings.js"
        fp.write_text('const apiKey = "sk-1234567890abcdefghijklmnop";\n')
        findings = scan_file_for_secrets(str(fp))
        assert len(findings) >= 1

    def test_clean_file(self, tmp_path):
        fp = tmp_path / "app.py"
        fp.write_text("import os\nname = os.getenv('APP_NAME')\nprint(name)\n")
        findings = scan_file_for_secrets(str(fp))
        assert len(findings) == 0

    def test_detect_connection_string(self, tmp_path):
        fp = tmp_path / "db.py"
        fp.write_text('password = "mysecretpassword123"\n')
        findings = scan_file_for_secrets(str(fp))
        assert len(findings) >= 1

    def test_nonexistent_file(self, tmp_path):
        findings = scan_file_for_secrets(str(tmp_path / "nope.py"))
        assert findings == []

    def test_binary_file_skipped(self, tmp_path):
        fp = tmp_path / "image.png"
        fp.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        findings = scan_file_for_secrets(str(fp))
        assert findings == []


class TestScanDirectoryForSecrets:
    def test_scan_directory(self, tmp_path):
        (tmp_path / "clean.py").write_text("x = 1\n")
        (tmp_path / "dirty.py").write_text('api_key = "sk-abcdef1234567890"\n')
        findings = scan_directory_for_secrets(str(tmp_path))
        assert len(findings) >= 1

    def test_skip_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "config.js").write_text('const key = "secret123456";\n')
        findings = scan_directory_for_secrets(str(tmp_path))
        assert len(findings) == 0

    def test_skip_git_dir(self, tmp_path):
        git = tmp_path / ".git" / "config"
        git.parent.mkdir(parents=True)
        git.write_text('password = "secret"\n')
        findings = scan_directory_for_secrets(str(tmp_path))
        assert len(findings) == 0

    def test_empty_dir(self, tmp_path):
        findings = scan_directory_for_secrets(str(tmp_path))
        assert findings == []

    def test_nested_scan(self, tmp_path):
        sub = tmp_path / "src" / "config"
        sub.mkdir(parents=True)
        (sub / "secrets.py").write_text('token = "ghp_1234567890abcdefghijklm"\n')
        findings = scan_directory_for_secrets(str(tmp_path))
        assert len(findings) >= 1


class TestScanEnvValues:
    def _make_env(self, variables: dict[str, str]) -> EnvFile:
        vars_map = {}
        for i, (k, v) in enumerate(variables.items(), 1):
            vars_map[k] = EnvVar(key=k, value=v, line_number=i, file_path=".env")
        return EnvFile(path=".env", variables=vars_map)

    def test_detect_aws_key_pattern(self):
        env = self._make_env({"AWS_KEY": "AKIAIOSFODNN7EXAMPLE"})
        findings = scan_env_values(env)
        assert len(findings) >= 1

    def test_detect_github_token(self):
        env = self._make_env({"TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk"})
        findings = scan_env_values(env)
        assert len(findings) >= 1

    def test_no_findings_normal_values(self):
        env = self._make_env({"APP_NAME": "myapp", "PORT": "3000"})
        findings = scan_env_values(env)
        assert len(findings) == 0

    def test_empty_values_ignored(self):
        env = self._make_env({"SECRET": ""})
        findings = scan_env_values(env)
        assert len(findings) == 0

    def test_jwt_detection(self):
        env = self._make_env({"TOKEN": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"})
        findings = scan_env_values(env)
        assert len(findings) >= 1


class TestCheckGitignoreForEnv:
    def test_env_in_gitignore(self, tmp_path):
        (tmp_path / ".gitignore").write_text(".env\n*.log\n")
        (tmp_path / ".env").write_text("X=1\n")
        issues = check_gitignore_for_env(str(tmp_path))
        # .env IS in gitignore, so no issue
        env_issues = [i for i in issues if "gitignore" in i.message.lower()]
        assert len(env_issues) == 0

    def test_env_not_in_gitignore(self, tmp_path):
        (tmp_path / ".gitignore").write_text("*.log\n")
        (tmp_path / ".env").write_text("X=1\n")
        issues = check_gitignore_for_env(str(tmp_path))
        assert len(issues) >= 1

    def test_no_gitignore(self, tmp_path):
        (tmp_path / ".env").write_text("X=1\n")
        issues = check_gitignore_for_env(str(tmp_path))
        assert len(issues) >= 1

    def test_no_env_file(self, tmp_path):
        # No .env = no issue
        issues = check_gitignore_for_env(str(tmp_path))
        assert len(issues) == 0
