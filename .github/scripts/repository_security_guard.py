#!/usr/bin/env python3
"""Repository Security Guard v2 — structural workflow trust-boundary check.

Parses every workflow under .github/workflows with a real YAML parser and
fails closed on:

  * privileged triggers: pull_request_target, workflow_run
  * write-capable GITHUB_TOKEN: `write-all`, any `<scope>: write`, or a
    workflow with no top-level `permissions` block (the default may be write)
  * actions/checkout without `persist-credentials: false`
  * third-party actions not pinned to a full 40-character commit SHA, and
    docker:// actions not pinned to an image digest
  * any workflow that cannot be parsed

Unlike v1, this guard also checks its own workflow file. Keep one canonical
copy of this script across repositories (see CANONICAL_SOURCE below).

Exit codes: 0 = pass, 1 = blocking findings, 2 = guard could not run.
"""
from __future__ import annotations

import pathlib
import re
import sys

CANONICAL_SOURCE = "altrudev/ddc:.github/scripts/repository_security_guard.py"
GUARD_VERSION = 2

WORKFLOWS = pathlib.Path(".github/workflows")
PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}
SHA = re.compile(r"^[0-9a-f]{40}$")
DOCKER_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
NETWORK = re.compile(r"\b(curl|wget|scp|rsync|nc|ncat|socat)\b", re.I)
SECRETS = re.compile(r"\$\{\{\s*secrets\.", re.I)


def load_yaml():
    try:
        import yaml  # type: ignore
    except Exception:  # pragma: no cover - environment dependent
        print("::error::PyYAML is required; refusing to run the guard without a real parser", file=sys.stderr)
        sys.exit(2)

    # GitHub Actions reads workflows as YAML 1.2, where `on` is a plain string.
    # PyYAML's default (YAML 1.1) loader turns `on`/`yes`/`no` into booleans, so
    # use a loader that only resolves booleans for true/false.
    class Loader(yaml.SafeLoader):
        pass

    for first, mappings in list(Loader.yaml_implicit_resolvers.items()):
        Loader.yaml_implicit_resolvers[first] = [
            (tag, rx) for tag, rx in mappings if tag != "tag:yaml.org,2002:bool"
        ]
    Loader.add_implicit_resolver(
        "tag:yaml.org,2002:bool",
        re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
        list("tTfF"),
    )
    return yaml, Loader


def triggers(on_value) -> set[str]:
    if isinstance(on_value, str):
        return {on_value}
    if isinstance(on_value, list):
        return {str(item) for item in on_value}
    if isinstance(on_value, dict):
        return {str(key) for key in on_value}
    return set()


def permission_problems(value, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        if value.strip().lower() == "write-all":
            return [f"{where}: permissions: write-all grants every write scope to GITHUB_TOKEN"]
        if value.strip().lower() in {"read-all", ""}:
            return []
        return [f"{where}: unrecognised permissions value {value!r}"]
    if isinstance(value, dict):
        writes = sorted(str(k) for k, v in value.items() if str(v).strip().lower() == "write")
        if writes:
            return [f"{where}: write permission granted for {', '.join(writes)}"]
        return []
    return [f"{where}: permissions must be a string or a mapping"]


def check_uses(spec: str, where: str, errors: list[str]) -> None:
    spec = spec.strip()
    if spec.startswith("./"):
        return
    if spec.startswith("docker://"):
        if not DOCKER_DIGEST.search(spec):
            errors.append(f"{where}: docker action not pinned to an image digest: {spec}")
        return
    if "@" not in spec:
        errors.append(f"{where}: action has no ref: {spec}")
        return
    _, ref = spec.rsplit("@", 1)
    if not SHA.fullmatch(ref):
        errors.append(f"{where}: action not pinned to a full commit SHA: {spec}")


def check_workflow(path: pathlib.Path, yaml, Loader, errors: list[str], warnings: list[str]) -> None:
    rel = path.as_posix()
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        doc = yaml.load(text, Loader=Loader)
    except Exception as exc:
        errors.append(f"{rel}: workflow is not valid YAML ({exc.__class__.__name__}); refusing to trust it")
        return
    if not isinstance(doc, dict):
        errors.append(f"{rel}: workflow root must be a mapping")
        return

    bad = triggers(doc.get("on")) & PRIVILEGED_TRIGGERS
    for trigger in sorted(bad):
        errors.append(f"{rel}: privileged trigger `{trigger}` can run untrusted code with repository secrets")

    if "permissions" not in doc:
        errors.append(f"{rel}: no top-level `permissions` block; declare `permissions: {{contents: read}}`")
    errors.extend(permission_problems(doc.get("permissions"), rel))

    if SECRETS.search(text) and NETWORK.search(text):
        warnings.append(f"{rel}: uses secrets and network-capable shell commands; review for exfiltration risk")

    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        errors.append(f"{rel}: `jobs` must be a mapping")
        return
    for job_id, job in jobs.items():
        where = f"{rel}:jobs.{job_id}"
        if not isinstance(job, dict):
            errors.append(f"{where}: job must be a mapping")
            continue
        errors.extend(permission_problems(job.get("permissions"), where))
        if "uses" in job:  # reusable workflow call
            check_uses(str(job["uses"]), where, errors)
        for index, step in enumerate(job.get("steps") or []):
            if not isinstance(step, dict) or "uses" not in step:
                continue
            spec = str(step["uses"])
            step_where = f"{where}.steps[{index}]"
            check_uses(spec, step_where, errors)
            if spec.split("@", 1)[0].lower() == "actions/checkout":
                persist = (step.get("with") or {}).get("persist-credentials")
                if str(persist).strip().lower() != "false":
                    errors.append(f"{step_where}: actions/checkout must set `persist-credentials: false`")


def main() -> int:
    yaml, Loader = load_yaml()
    errors: list[str] = []
    warnings: list[str] = []
    if WORKFLOWS.exists():
        files = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
        for path in files:  # no self-skip: the guard's own workflow is checked too
            check_workflow(path, yaml, Loader, errors, warnings)
    for item in warnings:
        print(f"::warning::{item}")
    for item in errors:
        print(f"::error::{item}")
    if errors:
        print(f"Repository security guard v{GUARD_VERSION} failed with {len(errors)} blocking finding(s).", file=sys.stderr)
        return 1
    print(f"Repository security guard v{GUARD_VERSION} passed with {len(warnings)} warning(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
