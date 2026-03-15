"""Tests for env_guard.diff."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from env_guard.diff import (
    compare_with_example,
    diff_env_files,
    merge_env_files,
    sync_env_with_example,
)
from env_guard.models import EnvFile, EnvVar, IssueType
from env_guard.parser import parse_env_file


def make_env(variables: dict[str, str], path: str = ".env") -> EnvFile:
    vars_map = {}
    for i, (k, v) in enumerate(variables.items(), 1):
        vars_map[k] = EnvVar(key=k, value=v, line_number=i, file_path=path)
    return EnvFile(path=path, variables=vars_map)


class TestDiffEnvFiles:
    def test_identical(self):
        a = make_env({"X": "1", "Y": "2"}, ".env")
        b = make_env({"X": "1", "Y": "2"}, ".env.prod")
        d = diff_env_files(a, b)
        assert d.has_differences is False
        assert len(d.same) == 2

    def test_missing_in_target(self):
        a = make_env({"X": "1", "Y": "2"}, ".env")
        b = make_env({"X": "1"}, ".env.prod")
        d = diff_env_files(a, b)
        assert "Y" in d.missing_in_target
        assert d.has_differences is True

    def test_missing_in_source(self):
        a = make_env({"X": "1"}, ".env")
        b = make_env({"X": "1", "Z": "3"}, ".env.prod")
        d = diff_env_files(a, b)
        assert "Z" in d.missing_in_source

    def test_different_values(self):
        a = make_env({"X": "1"}, ".env")
        b = make_env({"X": "99"}, ".env.prod")
        d = diff_env_files(a, b)
        assert len(d.different_values) == 1
        assert d.different_values[0][0] == "X"

    def test_complex_diff(self):
        a = make_env({"A": "1", "B": "2", "C": "3"}, ".env")
        b = make_env({"B": "2", "C": "99", "D": "4"}, ".env.prod")
        d = diff_env_files(a, b)
        assert "A" in d.missing_in_target
        assert "D" in d.missing_in_source
        assert any(v[0] == "C" for v in d.different_values)
        assert "B" in d.same

    def test_total_keys(self):
        a = make_env({"A": "1", "B": "2"}, ".env")
        b = make_env({"B": "2", "C": "3"}, ".env.prod")
        d = diff_env_files(a, b)
        assert d.total_keys == 3  # A, B, C


class TestCompareWithExample:
    def test_missing_in_env(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("A=1\n")
        example = tmp_path / ".env.example"
        example.write_text("A=1\nB=2\n")
        issues = compare_with_example(str(env), str(example))
        missing = [i for i in issues if i.type == IssueType.MISSING_IN_EXAMPLE or "missing" in i.message.lower()]
        assert len(missing) >= 1

    def test_extra_in_env(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("A=1\nB=2\n")
        example = tmp_path / ".env.example"
        example.write_text("A=1\n")
        issues = compare_with_example(str(env), str(example))
        extra = [i for i in issues if i.type == IssueType.EXTRA_IN_EXAMPLE or "extra" in i.message.lower() or "not in" in i.message.lower()]
        assert len(extra) >= 1

    def test_no_differences(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("A=1\nB=2\n")
        example = tmp_path / ".env.example"
        example.write_text("A=x\nB=y\n")
        issues = compare_with_example(str(env), str(example))
        # Same keys, different values — no missing issues
        missing = [i for i in issues if i.type == IssueType.MISSING_IN_EXAMPLE]
        assert len(missing) == 0


class TestSyncEnvWithExample:
    def test_add_missing(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("A=1\n")
        example = tmp_path / ".env.example"
        example.write_text("A=x\nB=new-value\n")
        changes = sync_env_with_example(str(env), str(example))
        assert len(changes) >= 1
        # Verify file was updated
        content = env.read_text()
        assert "B=" in content

    def test_no_changes_needed(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("A=1\nB=2\n")
        example = tmp_path / ".env.example"
        example.write_text("A=x\nB=y\n")
        changes = sync_env_with_example(str(env), str(example))
        assert len(changes) == 0

    def test_dry_run(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("A=1\n")
        example = tmp_path / ".env.example"
        example.write_text("A=x\nB=new\n")
        original = env.read_text()
        changes = sync_env_with_example(str(env), str(example), dry_run=True)
        assert len(changes) >= 1
        # File should NOT be modified
        assert env.read_text() == original


class TestMergeEnvFiles:
    def test_basic_merge(self):
        base = make_env({"A": "1", "B": "2"}, ".env")
        overlay = make_env({"B": "99", "C": "3"}, ".env.local")
        merged = merge_env_files(base, overlay)
        assert merged.variables["A"].value == "1"
        assert merged.variables["B"].value == "99"
        assert merged.variables["C"].value == "3"

    def test_overlay_wins(self):
        base = make_env({"X": "base"}, ".env")
        overlay = make_env({"X": "overlay"}, ".env.local")
        merged = merge_env_files(base, overlay)
        assert merged.variables["X"].value == "overlay"

    def test_empty_overlay(self):
        base = make_env({"A": "1"}, ".env")
        overlay = make_env({}, ".env.local")
        merged = merge_env_files(base, overlay)
        assert merged.variables["A"].value == "1"
        assert merged.count == 1

    def test_empty_base(self):
        base = make_env({}, ".env")
        overlay = make_env({"A": "1"}, ".env.local")
        merged = merge_env_files(base, overlay)
        assert merged.variables["A"].value == "1"
