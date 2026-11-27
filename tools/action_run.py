"""Prepare and run the composite action using only the checker's own Python modules."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tink_compat import check
from tink_compat.__main__ import incomplete, run_resolved
from tink_compat.prepare import PrepareError, SUPPORTED, adapter_fingerprint
from tink_compat.project import project_languages, resolve_project

OPTIONS = ("python_lock", "go_module", "go_list", "java_dependencies")


def output(key, value):
    value = str(value)
    if "\n" in value or "\r" in value:
        raise ValueError("Invalid multiline action output.")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        print(f"{key}={value}", file=stream)


def workspace_path(value):
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
    path = (root / value).resolve()
    if path == root or not path.is_relative_to(root):
        raise ValueError("Choose a path inside the consumer workspace.")
    return path


def tool_revision():
    repo, ref = os.environ.get("ACTION_REPO", ""), os.environ.get("ACTION_REF", "")
    if ROOT == Path(os.environ["GITHUB_WORKSPACE"]).resolve() or not repo or not ref:
        import subprocess
        return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    if re.fullmatch(r"[a-f0-9]{40}", ref):
        return ref
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        raise ValueError("Invalid action repository identifier.")
    url = f"https://api.github.com/repos/{repo}/commits/{quote(ref, safe='')}"
    req = Request(url, headers={"Accept": "application/vnd.github.sha", "User-Agent": "tink-release-compat"})
    with urlopen(req, timeout=20) as result:
        sha = result.read(100).decode().strip()
    if not re.fullmatch(r"[a-f0-9]{40}", sha):
        raise ValueError("The action ref did not resolve to a Git commit.")
    return sha


def save(directory, state):
    (directory / "plan.json").write_text(json.dumps(state), encoding="utf-8")


def begin():
    directory = Path(tempfile.mkdtemp(prefix="tink-plan-", dir=os.environ["RUNNER_TEMP"]))
    trees = Path(tempfile.mkdtemp(prefix=".tink-revisions-", dir=os.environ["GITHUB_WORKSPACE"]))
    output("plan-dir", directory)
    output("trees", trees.name)
    state = {"trees": str(trees.resolve()), "revision": "unresolved", "options": {}, "offline": False}
    try:
        state["out"] = str(workspace_path(os.environ["REPORT_DIR"]))
        state["revision"] = tool_revision()
        mode = os.environ["MODE"]
        if mode == "auto":
            mode = "profile" if os.environ["PROFILE"] else "project"
        if mode not in ("project", "sample", "profile"):
            raise ValueError("mode must be project, sample or profile.")
        if bool(os.environ["PROFILE"]) != (mode == "profile"):
            raise ValueError("Supply a profile path only in profile mode.")
        state["mode"] = mode
        state["profile_path"] = str(workspace_path(os.environ["PROFILE"]) if mode == "profile" else check.DEFAULT_PROFILE)
        state["options"] = {key: os.environ.get(key.upper()) or None for key in OPTIONS}
        if mode == "project" and not all(re.fullmatch(r"[0-9a-f]{40}", os.environ.get(k, "")) for k in ("BASE_SHA", "HEAD_SHA")):
            raise ValueError("Project mode requires a pull request with base and head SHAs. For a reference run select mode: sample.")
        if mode != "project" and any(state["options"].values()):
            raise ValueError("Dependency paths apply to project mode.")
        offline = os.environ["OFFLINE"].lower()
        if offline not in ("true", "false"):
            raise ValueError("offline must be true or false.")
        state.update(base_revision=os.environ["BASE_SHA"], head_revision=os.environ["HEAD_SHA"], offline=offline == "true")
        output("mode", mode)
    except (ValueError, OSError) as exc:
        state["error"] = str(exc)
    save(directory, state)


def inputs(state):
    trees = Path(state["trees"])
    return trees / "base", trees / "head"


def languages(state):
    if state["mode"] == "project":
        langs = project_languages(*inputs(state), **state["options"])
    else:
        state["profile"] = json.loads(Path(state["profile_path"]).read_bytes())
        langs, _ = check._validate_profile(state["profile"])
    for language in ("go", "java"):
        output(language, str(language in langs).lower())


def resolve(state):
    if state["mode"] == "project":
        profile, metadata = resolve_project(*inputs(state), **state["options"], base_revision=state["base_revision"],
                                            head_revision=state["head_revision"], offline=state["offline"])
        state.update(profile=profile, project=metadata)
    langs, versions = check._validate_profile(state["profile"])
    for language in langs:
        for index, version in enumerate(dict.fromkeys(versions[phase][language] for phase in ("baseline", "candidate"))):
            if version not in SUPPORTED[language]:
                raise ValueError(f"Unsupported {language} release {version}. Supported: {', '.join(sorted(SUPPORTED[language]))}.")
            fingerprint = adapter_fingerprint(language, version)
            slot = f"{language}{index}"
            output(f"{slot}-key", f"tink-adapter-{os.environ['RUNNER_OS']}-{os.environ['RUNNER_ARCH']}-{language}-{version}-{fingerprint}")
            output(f"{slot}-path", Path(os.environ["RUNNER_TEMP"]) / "tink-compat-adapters" / language / version)


def run(state, directory):
    out = Path(state.get("out", directory / "report"))
    cache = Path(os.environ["RUNNER_TEMP"]) / "tink-compat-adapters"
    error = state.get("error")
    if not error and os.environ.get("PRIOR_STATUS", "success") != "success":
        error = "A required checkout or toolchain setup step failed; see the preceding action step."
    if error:
        result, code = incomplete(out, state["revision"], error, state.get("project"))
    elif state["mode"] == "project":
        result, code = run_resolved(state["profile"], state["project"], out, cache, state["offline"], state["revision"])
    else:
        result, code = check.run_check(Path(state["profile_path"]), check.DEFAULT_VECTORS, out, cache, state["offline"], state["revision"])
    output("report-json", out / "report.json")
    output("report-md", out / "report.md")
    output("status", result["status"])
    summary = (out / "report.md").read_text(encoding="utf-8")
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
        stream.write(summary)
    print(f"{result['status']} ({out / 'report.md'})")
    return code


def main():
    command = sys.argv[1]
    if command == "begin":
        begin()
        return 0
    directory = Path(os.environ["PLAN_DIR"])
    state = json.loads((directory / "plan.json").read_bytes())
    if command == "run":
        try:
            return run(state, directory)
        finally:
            trees = Path(state["trees"])
            workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve()
            if trees.parent == workspace and trees.name.startswith(".tink-revisions-") and not trees.is_symlink():
                shutil.rmtree(trees)

    if not state.get("error"):
        try:
            {"languages": languages, "resolve": resolve}[command](state)
        except (ValueError, OSError, PrepareError) as exc:
            state["error"] = str(exc)
            print(f"INCOMPLETE: {exc}")
    save(directory, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
