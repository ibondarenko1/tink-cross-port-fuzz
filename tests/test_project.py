from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

import tink_compat.project as project_module
from tink_compat.project import ProjectInputError, discover_languages, resolve_project, stamp_export


GO_MOD = """module example.invalid/service

go 1.24.0

require github.com/tink-crypto/tink-go/v2 v{version}
"""


def _checkout(root: Path, *, python: str, go: str, go_list: str | None = None) -> Path:
    root.mkdir()
    (root / "requirements.txt").write_text(f"tink=={python}\nrequests==2.32.0\n", encoding="utf-8")
    (root / "go.mod").write_text(GO_MOD.format(version=go), encoding="utf-8")
    if go_list is not None:
        (root / "go-list.json").write_text(go_list, encoding="utf-8")
        stamp_export(root, go_list="go-list.json")
    return root


def _go_list(version: str) -> str:
    return json.dumps(
        {
            "Path": "github.com/tink-crypto/tink-go/v2",
            "Version": f"v{version}",
            "GoVersion": "1.24.0",
        }
    )


def test_resolve_project_returns_profile_and_provenance(tmp_path: Path):
    base = _checkout(tmp_path / "base", python="1.15.0", go="2.5.0", go_list=_go_list("2.5.0"))
    head = _checkout(tmp_path / "head", python="1.16.1", go="2.9.0", go_list=_go_list("2.9.0"))

    profile, metadata = resolve_project(
        base,
        head,
        go_list="go-list.json",
    )

    assert profile["languages"] == ["python", "go"]
    assert profile["baseline"] == {"python": "1.15.0", "go": "2.5.0"}
    assert profile["candidate"] == {"python": "1.16.1", "go": "2.9.0"}
    assert metadata["base_revision"] is None
    assert metadata["head_revision"] is None
    assert metadata["baseline"]["languages"]["go"]["declared_version"] == "2.5.0"
    assert metadata["candidate"]["languages"]["go"]["resolved_version"] == "2.9.0"
    assert all(len(value) == 64 for value in metadata["manifest_hashes"]["baseline"])


def test_nested_go_module_and_mvs_selection_are_recorded(tmp_path: Path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    for root, declared, selected in ((base, "2.5.0", "2.9.0"), (head, "2.9.0", "2.9.0")):
        (root / "services" / "verifier").mkdir(parents=True)
        (root / "requirements.txt").write_text("tink==1.15.0\n", encoding="utf-8")
        module = root / "services" / "verifier" / "go.mod"
        module.write_text(GO_MOD.format(version=declared), encoding="utf-8")
        (root / "services" / "verifier" / "go-list.json").write_text(
            _go_list(selected), encoding="utf-8"
        )
        stamp_export(
            root,
            go_list="services/verifier/go-list.json",
            go_module="services/verifier",
        )
    profile, metadata = resolve_project(
        base,
        head,
        go_module="services/verifier",
        go_list="services/verifier/go-list.json",
    )
    assert profile["baseline"]["go"] == "2.9.0"
    assert metadata["baseline"]["languages"]["go"]["declared_version"] == "2.5.0"
    assert metadata["baseline"]["languages"]["go"]["resolved_version"] == "2.9.0"
    assert metadata["baseline"]["languages"]["go"]["path"] == "services/verifier/go.mod"


def test_discover_languages_does_not_run_resolution(tmp_path: Path):
    root = _checkout(tmp_path / "project", python="1.15.0", go="2.5.0")
    assert discover_languages(root) == ["python", "go"]


def test_python_markers_are_rejected(tmp_path: Path):
    base = _checkout(tmp_path / "base", python="1.15.0", go="2.5.0", go_list=_go_list("2.5.0"))
    head = _checkout(tmp_path / "head", python="1.16.1", go="2.9.0", go_list=_go_list("2.9.0"))
    (head / "requirements.txt").write_text(
        "tink==1.16.1; python_version >= '3.12'\n", encoding="utf-8"
    )
    with pytest.raises(ProjectInputError, match="environment marker"):
        resolve_project(base, head, go_list="go-list.json")


@pytest.mark.parametrize("line", ["--index-url https://mirror.invalid/simple", "-e ../custom-tink"])
def test_python_source_changing_options_are_rejected(tmp_path: Path, line: str):
    base = _checkout(tmp_path / "base", python="1.15.0", go="2.5.0", go_list=_go_list("2.5.0"))
    head = _checkout(tmp_path / "head", python="1.16.1", go="2.9.0", go_list=_go_list("2.9.0"))
    (head / "requirements.txt").write_text(f"{line}\ntink==1.16.1\n", encoding="utf-8")
    with pytest.raises(ProjectInputError, match="source-changing"):
        resolve_project(base, head, go_list="go-list.json")


def test_go_replacements_are_rejected(tmp_path: Path):
    base = _checkout(tmp_path / "base", python="1.15.0", go="2.5.0", go_list=_go_list("2.5.0"))
    head = _checkout(tmp_path / "head", python="1.16.1", go="2.9.0", go_list=_go_list("2.9.0"))
    (head / "go.mod").write_text(
        GO_MOD.format(version="2.9.0")
        + "replace github.com/tink-crypto/tink-go/v2 => ../fork\n",
        encoding="utf-8",
    )
    stamp_export(head, go_list="go-list.json")
    with pytest.raises(ProjectInputError, match="replaces"):
        resolve_project(base, head, go_list="go-list.json")


def test_supplied_go_export_rejects_stale_manifest(tmp_path: Path):
    base = _checkout(tmp_path / "base", python="1.15.0", go="2.5.0", go_list=_go_list("2.5.0"))
    head = _checkout(tmp_path / "head", python="1.16.1", go="2.9.0", go_list=_go_list("2.9.0"))
    (head / "go.mod").write_text(GO_MOD.format(version="2.8.0"), encoding="utf-8")
    with pytest.raises(ProjectInputError, match="stale"):
        resolve_project(base, head, go_list="go-list.json")


def test_explicit_manifest_cannot_escape_checkout(tmp_path: Path):
    base = _checkout(tmp_path / "base", python="1.15.0", go="2.5.0", go_list=_go_list("2.5.0"))
    head = _checkout(tmp_path / "head", python="1.16.1", go="2.9.0", go_list=_go_list("2.9.0"))
    with pytest.raises(ProjectInputError, match="relative"):
        resolve_project(base, head, python_lock="../requirements.txt", go_list="go-list.json")


def test_supplied_revision_must_match_clean_checkout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    base = _checkout(tmp_path / "base", python="1.15.0", go="2.5.0", go_list=_go_list("2.5.0"))
    head = _checkout(tmp_path / "head", python="1.16.1", go="2.9.0", go_list=_go_list("2.9.0"))
    monkeypatch.setattr(project_module, "_git_revision", lambda root, used_paths=(): ("actual", True))
    with pytest.raises(ProjectInputError, match="does not match"):
        resolve_project(base, head, go_list="go-list.json", base_revision="wrong", head_revision="actual")


def test_ignored_export_cannot_be_attached_to_exact_revision(tmp_path: Path):
    git = shutil.which("git")
    if not git:
        pytest.skip("git is unavailable")
    roots: list[Path] = []
    revisions: list[str] = []
    for name, python, go in (("base", "1.15.0", "2.5.0"), ("head", "1.16.1", "2.9.0")):
        root = _checkout(tmp_path / name, python=python, go=go, go_list=_go_list(go))
        roots.append(root)
        (root / ".gitignore").write_text("go-list.json*\n", encoding="utf-8")
        subprocess.run([git, "-C", str(root), "init", "-q"], check=True)
        subprocess.run([git, "-C", str(root), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run([git, "-C", str(root), "config", "user.name", "Test"], check=True)
        subprocess.run([git, "-C", str(root), "add", "requirements.txt", "go.mod", ".gitignore"], check=True)
        subprocess.run([git, "-C", str(root), "commit", "-qm", "inputs"], check=True)
        revisions.append(
            subprocess.run(
                [git, "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        )
    with pytest.raises(ProjectInputError, match="dirty"):
        resolve_project(
            roots[0],
            roots[1],
            go_list="go-list.json",
            base_revision=revisions[0],
            head_revision=revisions[1],
        )


def test_maven_export_is_supported_as_second_verifier(tmp_path: Path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    for root, version in ((base, "1.18.0"), (head, "1.24.0")):
        root.mkdir()
        (root / "requirements.txt").write_text("tink==1.15.0\n", encoding="utf-8")
        (root / "dependencies.txt").write_text(
            f"[INFO]    com.google.crypto.tink:tink:jar:{version}:compile\n", encoding="utf-8"
        )
        (root / "pom.xml").write_text(
            "<project><dependencies><dependency><groupId>com.google.crypto.tink</groupId>"
            f"<artifactId>tink</artifactId><version>{version}</version></dependency></dependencies></project>",
            encoding="utf-8",
        )
        stamp_export(root, java_dependencies="dependencies.txt")
    profile, metadata = resolve_project(base, head, java_dependencies="dependencies.txt")
    assert profile["languages"] == ["python", "java"]
    assert profile["baseline"]["java"] == "1.18.0"
    assert metadata["candidate"]["languages"]["java"]["resolution"] == "maven-export"


def test_maven_pom_alone_is_incomplete(tmp_path: Path):
    base = _checkout(tmp_path / "base", python="1.15.0", go="2.5.0", go_list=_go_list("2.5.0"))
    head = _checkout(tmp_path / "head", python="1.16.1", go="2.9.0", go_list=_go_list("2.9.0"))
    pom = """<project><dependencies><dependency><groupId>com.google.crypto.tink</groupId><artifactId>tink</artifactId><version>1.24.0</version></dependency></dependencies></project>"""
    (head / "pom.xml").write_text(pom, encoding="utf-8")
    with pytest.raises(ProjectInputError, match="resolved dependency export"):
        resolve_project(base, head, go_list="go-list.json")


def test_supplied_maven_export_rejects_stale_pom(tmp_path: Path):
    base = tmp_path / "base"
    head = tmp_path / "head"
    for root, version in ((base, "1.18.0"), (head, "1.24.0")):
        root.mkdir()
        (root / "requirements.txt").write_text("tink==1.15.0\n", encoding="utf-8")
        (root / "pom.xml").write_text(
            "<project><dependencies><dependency><groupId>com.google.crypto.tink</groupId>"
            f"<artifactId>tink</artifactId><version>{version}</version></dependency></dependencies></project>",
            encoding="utf-8",
        )
        (root / "dependencies.txt").write_text(
            f"com.google.crypto.tink:tink:jar:{version}:compile\n", encoding="utf-8"
        )
        stamp_export(root, java_dependencies="dependencies.txt")
    (head / "pom.xml").write_text((head / "pom.xml").read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ProjectInputError, match="stale"):
        resolve_project(base, head, java_dependencies="dependencies.txt")
