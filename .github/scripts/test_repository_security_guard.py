#!/usr/bin/env python3
"""Regression tests for repository_security_guard.py.

Every case here bypassed guard v1 (audit 2026-10-29, finding H1).
Run from the repository root: python .github/scripts/test_repository_security_guard.py
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

GUARD = pathlib.Path(__file__).resolve().with_name("repository_security_guard.py")
PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"
SAFE_JOBS = f"""permissions:
  contents: read
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PIN}
        with:
          persist-credentials: false
"""


def run_guard(files: dict[str, str]) -> int:
    with tempfile.TemporaryDirectory() as root:
        wf = pathlib.Path(root, ".github", "workflows")
        wf.mkdir(parents=True)
        for name, text in files.items():
            (wf / name).write_text(text, encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", str(GUARD)], cwd=root,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ},
        ).returncode


class GuardTests(unittest.TestCase):
    def assertBlocked(self, text: str, name: str = "a.yml") -> None:
        self.assertEqual(run_guard({name: text}), 1, text)

    def test_safe_workflow_passes(self):
        self.assertEqual(run_guard({"a.yml": "on: push\n" + SAFE_JOBS}), 0)

    def test_privileged_trigger_spellings(self):
        for on in (
            "on:\n  pull_request_target:\n",
            "on: pull_request_target\n",
            "on: [push, pull_request_target]\n",
            "on:\n  - pull_request_target\n",
            '"on":\n  pull_request_target: {}\n',
            "on: workflow_run\n",
        ):
            with self.subTest(on=on):
                self.assertBlocked(on + SAFE_JOBS)

    def test_write_permissions(self):
        for perms in (
            'permissions: "write-all"\n',
            "permissions: write-all\n",
            "permissions:\n  contents: write\n",
            "permissions: {actions: write, id-token: write}\n",
        ):
            with self.subTest(perms=perms):
                self.assertBlocked("on: push\n" + perms + "jobs: {}\n")

    def test_missing_permissions(self):
        self.assertBlocked("on: push\njobs: {}\n")

    def test_job_level_write(self):
        self.assertBlocked(
            "on: push\npermissions: {contents: read}\njobs:\n  x:\n"
            "    permissions: {id-token: write}\n    runs-on: u\n    steps: []\n"
        )

    def test_guard_workflow_is_not_skipped(self):
        self.assertBlocked("on: pull_request_target\n" + SAFE_JOBS, name="repository-security-guard.yml")

    def test_unpinned_actions(self):
        for uses in ("evil/action@main", "evil/action@v1", "evil/action", "docker://alpine:3"):
            with self.subTest(uses=uses):
                self.assertBlocked(
                    "on: push\npermissions: {contents: read}\njobs:\n  x:\n    runs-on: u\n"
                    f"    steps:\n      - uses: {uses}\n"
                )

    def test_unpinned_reusable_workflow(self):
        self.assertBlocked(
            "on: push\npermissions: {contents: read}\njobs:\n  x:\n"
            "    uses: org/repo/.github/workflows/w.yml@main\n"
        )

    def test_checkout_must_not_persist_credentials(self):
        for extra in ("", "        with:\n          persist-credentials: true\n"):
            with self.subTest(extra=extra):
                self.assertBlocked(
                    "on: push\npermissions: {contents: read}\njobs:\n  x:\n    runs-on: u\n"
                    f"    steps:\n      - uses: actions/checkout@{PIN}\n" + extra
                )

    def test_invalid_yaml_fails_closed(self):
        self.assertBlocked("on: push\n  bad: [\n")


if __name__ == "__main__":
    unittest.main(verbosity=1)
