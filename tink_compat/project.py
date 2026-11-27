"""Resolve a consumer project's Tink dependencies for a compatibility check.

The normal bundled profile is intentionally static.  This module is the
project-aware input path used by CI integrations: it reads two checked-out
revisions, resolves the package versions from lock or tool output, and returns
the same ``baseline``/``candidate`` profile shape as the static profile.

No project code is imported or executed.  The only subprocess used for input
resolution is ``go list -mod=readonly -m -json all``.  Python and Java inputs
are parsed from files or an explicitly exported Maven dependency report.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Iterable, Mapping


TINK_GO_MODULE = "github.com/tink-crypto/tink-go/v2"
TINK_JAVA_GROUP = "com.google.crypto.tink"
TINK_JAVA_ARTIFACT = "tink"


class ProjectInputError(ValueError):
    """The project cannot be represented as a deterministic compatibility profile."""


_VERSION = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")
_PYTHON_EXACT = re.compile(r"^([A-Za-z0-9_.-]+)(?:\[([^\]]+)\])?\s*==\s*([^\s;]+)(.*)$")
_GO_REQUIRE = re.compile(r"^\s*" + re.escape(TINK_GO_MODULE) + r"\s+(\S+)(?:\s+//.*)?$")
_MAVEN_COORDINATE = re.compile(
    r"(?:^|\s)" + re.escape(TINK_JAVA_GROUP) + r":" + re.escape(TINK_JAVA_ARTIFACT)
    + r":"
    r"(?:(?:jar|pom):)?"
    r"(?P<version>[^:\s]+)"
    r"(?::[^\s]+)*"
    r"(?:\s|$)"
)

_PYTHON_DISCOVERY = (
    "requirements.txt",
    "requirements-lock.txt",
    "requirements.lock",
    "pylock.toml",
    "uv.lock",
    "poetry.lock",
)
_GO_DISCOVERY = ("go.mod",)
_JAVA_DISCOVERY = ("pom.xml",)
_POM_EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "build",
    "dist",
    "target",
    "out",
    ".gradle",
    "node_modules",
    "vendor",
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _root(value: Path | str, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_dir():
        raise ProjectInputError(f"{label} project directory does not exist: {path}")
    return path.resolve()


def _relative_file(root: Path, value: str | Path, label: str) -> tuple[Path, str]:
    """Resolve a file path without allowing an escape from the checkout."""
    raw = Path(value)
    if raw.is_absolute():
        raise ProjectInputError(f"{label} must be relative to the project checkout")
    candidate = (root / raw).resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ProjectInputError(f"{label} must be relative to the project checkout and stay inside it") from exc
    if not candidate.is_file():
        raise ProjectInputError(f"{label} does not exist: {relative.as_posix()}")
    return candidate, relative.as_posix()


def _candidate_files(root: Path, names: Iterable[str]) -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
    for name in names:
        candidate = root / name
        if not candidate.exists():
            continue
        try:
            resolved, relative = _relative_file(root, name, "discovered manifest")
        except ProjectInputError:
            # A symlinked manifest outside the checkout is not a valid input.
            raise
        found.append((resolved, relative))
    return found


def _read_manifest(path: Path, relative: str, kind: str) -> tuple[str, bytes, dict[str, Any]]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ProjectInputError(f"cannot read {kind} manifest {relative}: {exc}") from exc
    return text, raw, {"path": relative, "kind": kind, "sha256": _sha256(raw)}


def _sidecar_path(export_path: Path) -> Path:
    return export_path.with_name(export_path.name + ".inputs.json")


def _safe_sidecar(root: Path, export_path: Path) -> tuple[Path, str]:
    candidate = _sidecar_path(export_path)
    if candidate.is_symlink():
        raise ProjectInputError(f"export sidecar is a symlink: {candidate.name}")
    resolved = candidate.resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise ProjectInputError("export sidecar points outside the project checkout") from exc
    return resolved, relative


def _repository_poms(root: Path) -> list[tuple[Path, str]]:
    """List repository-owned POMs in a deterministic, bounded scope."""
    result: list[tuple[Path, str]] = []
    for path in root.rglob("pom.xml"):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part in _POM_EXCLUDED_DIRS for part in relative.parts):
            continue
        try:
            resolved, relative_name = _relative_file(root, relative, "Maven POM")
        except ProjectInputError:
            # A POM symlink escaping the checkout is not repository-owned.
            raise
        result.append((resolved, relative_name))
    return sorted(result, key=lambda item: item[1])


def _input_manifest(path: Path, relative: str, kind: str, *, role: str | None = None) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProjectInputError(f"cannot read input manifest {relative}: {exc}") from exc
    value: dict[str, Any] = {"path": relative, "kind": kind, "sha256": _sha256(raw)}
    if role:
        value["role"] = role
    return value


def _export_inputs(
    root: Path,
    *,
    export_path: Path,
    export_relative: str,
    kind: str,
    go_module: str | Path | None = None,
) -> list[dict[str, Any]]:
    inputs: list[dict[str, Any]] = []
    if kind == "go-list":
        module_path, module_relative, module_dir = _select_go_module(root, go_module)
        inputs.append(_input_manifest(module_path, module_relative, "go-module", role="go.mod"))
        go_sum = module_dir / "go.sum"
        if go_sum.is_file():
            inputs.append(
                _input_manifest(
                    go_sum,
                    go_sum.relative_to(root).as_posix(),
                    "go-checksum-support",
                    role="go.sum",
                )
            )
    elif kind == "maven-dependencies":
        poms = _repository_poms(root)
        if not poms:
            raise ProjectInputError("Maven dependency export requires at least one repository-owned pom.xml")
        for path, relative in poms:
            inputs.append(_input_manifest(path, relative, "maven-pom-input", role="pom.xml"))
    else:
        raise ProjectInputError(f"unsupported export kind {kind}")
    return inputs


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    if temporary.is_symlink():
        raise ProjectInputError(f"export sidecar temporary path is a symlink: {temporary.name}")
    try:
        if temporary.exists() and temporary.resolve().parent != path.resolve().parent:
            raise ProjectInputError("export sidecar temporary path points outside the project checkout")
    except OSError as exc:
        raise ProjectInputError(f"cannot inspect export sidecar temporary path: {exc}") from exc
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def stamp_export(
    root: Path | str,
    *,
    go_list: str | Path | None = None,
    go_module: str | Path | None = None,
    java_dependencies: str | Path | None = None,
) -> Path:
    """Write input checksums beside a freshly generated dependency export.

    The returned path is the first sidecar written.  Supplying both export
    kinds writes one sidecar per export and still returns the Go sidecar first.
    """
    checkout = _root(root, "project")
    exports: list[tuple[Path, str, str]] = []
    if go_list is not None:
        path, relative = _relative_file(checkout, go_list, "Go list export")
        exports.append((path, relative, "go-list"))
    if java_dependencies is not None:
        path, relative = _relative_file(checkout, java_dependencies, "Maven dependency export")
        exports.append((path, relative, "maven-dependencies"))
    if not exports:
        raise ProjectInputError("stamp_export requires go_list or java_dependencies")
    sidecars: list[Path] = []
    for export_path, export_relative, kind in exports:
        try:
            export_raw = export_path.read_bytes()
        except OSError as exc:
            raise ProjectInputError(f"cannot read dependency export {export_relative}: {exc}") from exc
        inputs = _export_inputs(
            checkout,
            export_path=export_path,
            export_relative=export_relative,
            kind=kind,
            go_module=go_module,
        )
        sidecar, _ = _safe_sidecar(checkout, export_path)
        _write_json_atomic(
            sidecar,
            {
                "schema_version": 1,
                "export": {
                    "path": export_relative,
                    "kind": kind,
                    "sha256": _sha256(export_raw),
                },
                "inputs": inputs,
            },
        )
        sidecars.append(sidecar)
    return sidecars[0]


def _verify_export_sidecar(
    root: Path,
    export_path: Path,
    export_relative: str,
    kind: str,
    *,
    go_module: str | Path | None = None,
) -> tuple[dict[str, Any], Path, str]:
    sidecar, sidecar_relative = _safe_sidecar(root, export_path)
    if not sidecar.is_file():
        raise ProjectInputError(
            f"{kind} export {export_relative} is missing checksum sidecar {sidecar_relative}; run project.stamp_export"
        )
    try:
        sidecar_raw = sidecar.read_bytes()
        value = json.loads(sidecar_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectInputError(f"invalid {kind} export sidecar {sidecar_relative}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ProjectInputError(f"{kind} export sidecar {sidecar_relative} has unsupported schema")
    export = value.get("export")
    if not isinstance(export, dict) or export.get("path") != export_relative or export.get("kind") != kind:
        raise ProjectInputError(f"{kind} export sidecar {sidecar_relative} does not bind this export")
    if export.get("sha256") != _sha256(export_path.read_bytes()):
        raise ProjectInputError(f"{kind} export {export_relative} changed after its checksum sidecar was written")
    expected_inputs = _export_inputs(
        root,
        export_path=export_path,
        export_relative=export_relative,
        kind=kind,
        go_module=go_module,
    )
    supplied_inputs = value.get("inputs")
    if not isinstance(supplied_inputs, list):
        raise ProjectInputError(f"{kind} export sidecar {sidecar_relative} has no input manifest list")
    def key(item: Mapping[str, Any]) -> tuple[Any, Any]:
        return item.get("path"), item.get("role")
    expected_map = {key(item): item.get("sha256") for item in expected_inputs}
    supplied_map = {
        key(item): item.get("sha256")
        for item in supplied_inputs
        if isinstance(item, Mapping)
    }
    if supplied_map != expected_map:
        raise ProjectInputError(
            f"{kind} export sidecar {sidecar_relative} is stale for the current dependency manifests"
        )
    return {
        "path": sidecar_relative,
        "kind": "export-inputs-sidecar",
        "sha256": _sha256(sidecar_raw),
        "export_sha256": export["sha256"],
    }, sidecar, sidecar_relative


def _version(value: str, label: str) -> str:
    match = _VERSION.fullmatch(value.strip())
    if not match:
        raise ProjectInputError(f"{label} has unsupported Tink version {value!r}")
    return match.group(1)


def _version_key(value: str) -> tuple[int, int, int, str]:
    match = _VERSION.fullmatch(value)
    if not match:
        return (0, 0, 0, value)
    major, minor, patch = (int(part) for part in match.group(1).split(".")[:3])
    return major, minor, patch, match.group(1)


def _select_manifest(root: Path, explicit: str | Path | None, names: Iterable[str], label: str) -> tuple[Path, str]:
    if explicit is not None:
        return _relative_file(root, explicit, label)
    candidates = _candidate_files(root, names)
    if not candidates:
        raise ProjectInputError(
            f"{label} was not found. Pass an explicit path relative to the checkout"
        )
    if len(candidates) > 1:
        paths = ", ".join(relative for _, relative in candidates)
        raise ProjectInputError(f"ambiguous {label} manifests: {paths}")
    return candidates[0]


def _parse_python_lock(path: Path, relative: str) -> tuple[str, dict[str, Any]]:
    text, raw, manifest = _read_manifest(path, relative, "python-lock")
    versions: list[str] = []
    logical_lines: list[tuple[int, str]] = []
    continuation = ""
    continuation_line = 0
    for line_number, original in enumerate(text.splitlines(), 1):
        stripped = original.strip()
        if continuation:
            continuation += stripped
            if stripped.endswith("\\"):
                continuation = continuation[:-1] + " "
                continue
            logical_lines.append((continuation_line, continuation))
            continuation = ""
            continuation_line = 0
            continue
        if stripped.endswith("\\"):
            continuation = stripped[:-1] + " "
            continuation_line = line_number
            continue
        logical_lines.append((line_number, stripped))
    if continuation:
        logical_lines.append((continuation_line, continuation))
    for line_number, line in logical_lines:
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            raise ProjectInputError(
                f"Python lock {relative}:{line_number} contains a source-changing pip option or include"
            )
        if ";" in line:
            raise ProjectInputError(
                f"Python lock {relative}:{line_number} contains an environment marker"
            )
        # Inline comments are harmless after a requirement.  Options other
        # than hashes would change the resolution and are rejected below.
        line = re.split(r"\s+#", line, maxsplit=1)[0].rstrip()
        match = _PYTHON_EXACT.fullmatch(line)
        if not match:
            if re.match(r"(?i)^tink(?:\[|\s|[<>=!~@])", line):
                raise ProjectInputError(
                    f"Python lock {relative}:{line_number} must pin tink with an exact == version"
                )
            continue
        name, extras, version, rest = match.groups()
        if name.lower().replace("_", "-").replace(".", "-") != "tink":
            continue
        if extras:
            raise ProjectInputError(f"Python lock {relative}:{line_number} uses unsupported tink extras")
        if rest.strip() and not all(token.startswith("--hash=") for token in rest.split()):
            raise ProjectInputError(
                f"Python lock {relative}:{line_number} contains unsupported requirement options"
            )
        versions.append(_version(version, f"Python lock {relative}:{line_number}"))
    if not versions:
        raise ProjectInputError(f"Python lock {relative} has no exact tink== requirement")
    if len(set(versions)) != 1:
        raise ProjectInputError(f"Python lock {relative} has ambiguous tink versions: {sorted(set(versions))}")
    manifest.update(
        {
            "declared_version": versions[0],
            "resolved_version": versions[0],
            "resolution": "exact-requirement",
        }
    )
    return versions[0], manifest


def _parse_go_mod(path: Path, relative: str) -> tuple[str, dict[str, Any], str]:
    text, raw, manifest = _read_manifest(path, relative, "go-module")
    declared: str | None = None
    for line_number, original in enumerate(text.splitlines(), 1):
        line = original.split("//", 1)[0].strip()
        if line.startswith("replace"):
            # Replacements alter MVS and may be hidden in a grouped directive.
            # We do not claim to resolve such a graph, including replacements
            # of modules related to Tink, so require a clean module file.
            raise ProjectInputError(f"Go module {relative}:{line_number} replaces a module; replacement directives are unsupported")
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        match = _GO_REQUIRE.fullmatch(line)
        if match:
            value = _version(match.group(1), f"Go module {relative}:{line_number}")
            if declared is not None and declared != value:
                raise ProjectInputError(f"Go module {relative} declares multiple Tink versions")
            declared = value
    # A require block is common.  Parse its simple one-line entries as well.
    in_require = False
    for line_number, original in enumerate(text.splitlines(), 1):
        stripped = original.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if not in_require:
            continue
        line = original.split("//", 1)[0].strip()
        match = _GO_REQUIRE.fullmatch(line)
        if match:
            value = _version(match.group(1), f"Go module {relative}:{line_number}")
            if declared is not None and declared != value:
                raise ProjectInputError(f"Go module {relative} declares multiple Tink versions")
            declared = value
    if declared is None:
        raise ProjectInputError(f"Go module {relative} has no exact {TINK_GO_MODULE} requirement")
    manifest.update({"declared_version": declared})
    return declared, manifest, text


def _json_objects(text: str, label: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    index = 0
    objects: list[dict[str, Any]] = []
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError as exc:
            raise ProjectInputError(f"{label} is not valid JSON: {exc.msg}") from exc
        index = end
        if isinstance(value, list):
            if not all(isinstance(item, dict) for item in value):
                raise ProjectInputError(f"{label} must contain module objects")
            objects.extend(value)
        elif isinstance(value, dict):
            objects.append(value)
        else:
            raise ProjectInputError(f"{label} must contain module objects")
    return objects


def _parse_go_list(text: str, label: str) -> tuple[str, dict[str, Any]]:
    all_modules = _json_objects(text, label)
    for item in all_modules:
        if item.get("Replace"):
            path = item.get("Path") or "unknown module"
            raise ProjectInputError(f"{label} reports an unsupported replacement for {path}")
    modules = [item for item in all_modules if item.get("Path") == TINK_GO_MODULE]
    if len(modules) != 1:
        raise ProjectInputError(f"{label} must contain exactly one {TINK_GO_MODULE} module")
    module = modules[0]
    resolved = module.get("Version")
    if not isinstance(resolved, str) or not resolved:
        raise ProjectInputError(f"{label} has no resolved version for {TINK_GO_MODULE}")
    version = _version(resolved, label)
    canonical_modules: list[dict[str, Any]] = []
    for item in all_modules:
        value: dict[str, Any] = {}
        for key in ("Path", "Version", "Main", "GoVersion"):
            if key in item and isinstance(item[key], (str, bool)):
                value[key] = item[key]
        canonical_modules.append(value)
    canonical_modules.sort(key=lambda item: (str(item.get("Path", "")), str(item.get("Version", ""))))
    canonical = json.dumps(canonical_modules, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return version, {
        "resolved_version": version,
        "go_version": module.get("GoVersion") if isinstance(module.get("GoVersion"), str) else None,
        "module_path": TINK_GO_MODULE,
        "graph_sha256": _sha256(canonical),
        "graph_hash_method": "sha256-canonical-go-module-graph",
    }


def _select_go_module(root: Path, explicit: str | Path | None) -> tuple[Path, str, Path]:
    """Return ``go.mod``, its checkout-relative path, and module directory."""
    if explicit is None:
        path, relative = _relative_file(root, "go.mod", "Go module")
    else:
        raw = Path(explicit)
        if raw.is_absolute():
            raise ProjectInputError("Go module must be relative to the project checkout")
        candidate = (root / raw).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ProjectInputError("Go module must be relative to the project checkout and stay inside it") from exc
        if candidate.is_dir():
            candidate = candidate / "go.mod"
        # _relative_file performs the escape and file checks for both forms.
        path, relative = _relative_file(root, candidate.relative_to(root), "Go module")
    if path.name != "go.mod":
        raise ProjectInputError(f"Go module {relative} must refer to a go.mod file or its module directory")
    return path, relative, path.parent


def _go_workspace(module_dir: Path) -> Path | None:
    """Find a workspace file that could affect this module graph."""
    current = module_dir
    while True:
        candidate = current / "go.work"
        if candidate.is_file():
            return candidate
        if current.parent == current:
            return None
        current = current.parent


def _run_go_list(root: Path, *, offline: bool = False) -> tuple[str, bytes, str | None]:
    go = shutil.which("go")
    if not go:
        raise ProjectInputError("Go is required to resolve go.mod; provide an exported --go-list file")
    env = os.environ.copy()
    env["GOWORK"] = "off"
    env["GOTOOLCHAIN"] = "local"
    if offline:
        # Go still consults its module cache, but must never contact a proxy or
        # checksum service while an offline compatibility check is running.
        env["GOPROXY"] = "off"
        env["GOSUMDB"] = "off"
    try:
        process = subprocess.run(
            [go, "list", "-mod=readonly", "-m", "-json", "all"],
            cwd=str(root),
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProjectInputError(f"go list resolution failed: {exc}") from exc
    if process.returncode != 0:
        detail = (process.stderr or process.stdout or "").strip().splitlines()
        suffix = f": {detail[-1][:400]}" if detail else ""
        raise ProjectInputError(f"go list resolution failed with exit code {process.returncode}{suffix}")
    raw = (process.stdout or "").encode("utf-8")
    return process.stdout or "", raw, None


def _parse_java_export(path: Path, relative: str) -> tuple[str, dict[str, Any]]:
    text, raw, manifest = _read_manifest(path, relative, "maven-dependencies")
    versions: list[str] = []
    for match in _MAVEN_COORDINATE.finditer(text):
        versions.append(_version(match.group("version"), f"Maven dependency export {relative}"))
    if not versions:
        raise ProjectInputError(
            f"Maven dependency export {relative} has no resolved {TINK_JAVA_GROUP}:{TINK_JAVA_ARTIFACT} dependency"
        )
    if len(set(versions)) != 1:
        raise ProjectInputError(f"Maven dependency export {relative} has ambiguous Tink versions: {sorted(set(versions))}")
    manifest.update(
        {
            "declared_version": versions[0],
            "resolved_version": versions[0],
            "resolution": "maven-export",
        }
    )
    return versions[0], manifest


def _git_revision(root: Path, used_paths: Iterable[str] = ()) -> tuple[str | None, bool]:
    git = shutil.which("git")
    if not git or not (root / ".git").exists():
        return None, False
    try:
        revision = subprocess.run(
            [git, "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, check=False
        )
        if revision.returncode != 0:
            return None, False
        paths = sorted(set(path for path in used_paths if path))
        command = [
            git,
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored",
        ]
        if paths:
            command.extend(["--", *paths])
        status = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        value = revision.stdout.strip() or None
        return value, bool(value and status.returncode == 0 and not status.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return None, False


def _resolve_side(
    root: Path,
    *,
    python_lock: str | Path | None,
    go_module: str | Path | None,
    go_list: str | Path | None,
    java_dependencies: str | Path | None,
    offline: bool = False,
) -> dict[str, Any]:
    languages: dict[str, dict[str, Any]] = {}
    manifests: list[dict[str, Any]] = []
    python_candidates_exist = python_lock is not None or bool(_candidate_files(root, _PYTHON_DISCOVERY))
    try:
        python_path, python_relative = _select_manifest(root, python_lock, _PYTHON_DISCOVERY, "Python lock")
        python_version, python_manifest = _parse_python_lock(python_path, python_relative)
        languages["python"] = python_manifest
        manifests.append(python_manifest)
    except ProjectInputError:
        if python_candidates_exist:
            raise

    go_candidates_exist = go_module is not None or go_list is not None or (root / "go.mod").exists()
    try:
        go_path, go_relative, module_dir = _select_go_module(root, go_module)
        workspace = _go_workspace(module_dir)
        if workspace is not None:
            raise ProjectInputError(
                f"Go module {go_relative} is inside a Go workspace ({workspace.name}); workspace resolution is unsupported"
            )
        declared, go_manifest, _ = _parse_go_mod(go_path, go_relative)
        go_sum = module_dir / "go.sum"
        if go_sum.is_file():
            try:
                go_sum_raw = go_sum.read_bytes()
            except OSError as exc:
                raise ProjectInputError(f"cannot read Go checksum file {go_sum}: {exc}") from exc
            go_sum_relative = go_sum.relative_to(root).as_posix()
            go_sum_manifest = {
                "path": go_sum_relative,
                "kind": "go-checksum-support",
                "sha256": _sha256(go_sum_raw),
                "is_lock": False,
            }
        else:
            go_sum_manifest = None
        if go_list is not None:
            go_list_path, go_list_relative = _relative_file(root, go_list, "Go list export")
            list_text, list_raw, list_manifest = _read_manifest(go_list_path, go_list_relative, "go-list")
            list_manifest["provenance"] = "supplied-export"
            list_manifest["resolution_claim"] = "parsed-export-only"
            sidecar_manifest, _, _ = _verify_export_sidecar(
                root,
                go_list_path,
                go_list_relative,
                "go-list",
                go_module=go_module,
            )
        else:
            list_text, list_raw, _ = _run_go_list(module_dir, offline=offline)
            list_manifest = {
                "path": None,
                "kind": "go-list",
                "sha256": _sha256(list_raw),
                "source": "go list -mod=readonly -m -json all",
                "provenance": "executed-readonly-go-list",
                "resolution_claim": "module-graph",
            }
            sidecar_manifest = None
        resolved, resolution = _parse_go_list(list_text, list_manifest.get("path") or "go list output")
        if _version_key(resolved) < _version_key(declared):
            raise ProjectInputError(
                f"Go dependency export selected {resolved}, below go.mod declaration {declared}"
            )
        if go_list is not None:
            list_manifest["validation"] = {
                "module_path": TINK_GO_MODULE,
                "declared_version": declared,
                "selected_version": resolved,
                "freshness": "target-module-and-version-parsed",
            }
        go_manifest.update(resolution)
        go_manifest["resolution"] = "go-list-export" if go_list is not None else "go-list-readonly"
        go_manifest["declared_version"] = declared
        go_manifest["resolved_version"] = resolved
        go_manifest["independent_execution"] = go_list is None
        manifests.extend([go_manifest, list_manifest])
        if go_sum_manifest is not None:
            manifests.append(go_sum_manifest)
        if sidecar_manifest is not None:
            manifests.append(sidecar_manifest)
        languages["go"] = go_manifest
    except ProjectInputError:
        if go_candidates_exist:
            raise

    if java_dependencies is not None:
        java_path, java_relative = _relative_file(root, java_dependencies, "Maven dependency export")
        java_version, java_manifest = _parse_java_export(java_path, java_relative)
        sidecar_manifest, _, _ = _verify_export_sidecar(
            root,
            java_path,
            java_relative,
            "maven-dependencies",
        )
        for pom_path, pom_relative in _repository_poms(root):
            manifests.append(_input_manifest(pom_path, pom_relative, "maven-pom-input", role="pom.xml"))
        manifests.append(sidecar_manifest)
        java_manifest["declared_version"] = None
        java_manifest["declared_source"] = "not-independently-parsed"
        java_manifest["provenance"] = "supplied-export"
        java_manifest["independent_execution"] = False
        languages["java"] = java_manifest
        manifests.append(java_manifest)
    elif (root / "pom.xml").exists():
        raise ProjectInputError(
            "Maven pom.xml was found but no resolved dependency export was supplied. "
            "Pass --java-dependencies from a Maven dependency:list/tree export."
        )

    return {
        "revision": None,
        "revision_exact": False,
        "languages": languages,
        "manifests": manifests,
        "used_paths": sorted(
            set(item["path"] for item in manifests if isinstance(item.get("path"), str))
        ),
    }


def discover_languages(root: Path | str) -> list[str]:
    """Return likely adapter languages without running dependency resolution."""
    checkout = _root(root, "project")
    result: list[str] = []
    if any((checkout / name).is_file() for name in _PYTHON_DISCOVERY):
        result.append("python")
    if (checkout / "go.mod").is_file():
        result.append("go")
    if (checkout / "pom.xml").is_file():
        result.append("java")
    return result


def project_languages(
    base: Path | str,
    head: Path | str,
    *,
    python_lock: str | Path | None = None,
    go_module: str | Path | None = None,
    go_list: str | Path | None = None,
    java_dependencies: str | Path | None = None,
) -> set[str]:
    """Plan toolchain setup from bounded manifest detection.

    This helper performs no dependency resolution and starts no subprocesses.
    It returns the union of languages present in the two checkouts so an Action
    can install every tool needed before calling :func:`resolve_project`.
    Explicit paths are validated against each checkout and cannot escape it.
    """
    base_root = _root(base, "base")
    head_root = _root(head, "head")
    result: set[str] = set()
    roots = (base_root, head_root)
    if python_lock is not None:
        for root in roots:
            _relative_file(root, python_lock, "Python lock")
        result.add("python")
    elif any("python" in discover_languages(root) for root in roots):
        result.add("python")
    if go_module is not None:
        for root in roots:
            _select_go_module(root, go_module)
        result.add("go")
    elif go_list is not None or any((root / "go.mod").is_file() for root in roots):
        if go_list is not None:
            for root in roots:
                _relative_file(root, go_list, "Go list export")
        result.add("go")
    if java_dependencies is not None:
        for root in roots:
            _relative_file(root, java_dependencies, "Maven dependency export")
        result.add("java")
    elif any((root / "pom.xml").is_file() for root in roots):
        result.add("java")
    return result


def resolve_project(
    base: Path | str,
    head: Path | str,
    *,
    python_lock: str | Path | None = None,
    go_module: str | Path | None = None,
    go_list: str | Path | None = None,
    java_dependencies: str | Path | None = None,
    base_revision: str | None = None,
    head_revision: str | None = None,
    offline: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve baseline and candidate checkouts into a static-profile shape.

    ``go_list`` and the other path arguments are interpreted relative to both
    checkouts.  Supplying an exported Go module graph is useful in CI when the
    runner intentionally has no network.  If omitted, the resolver invokes Go
    with ``-mod=readonly`` and ``GOWORK=off``.
    """
    base_root = _root(base, "base")
    head_root = _root(head, "head")
    base_info = _resolve_side(
        base_root,
        python_lock=python_lock,
        go_module=go_module,
        go_list=go_list,
        java_dependencies=java_dependencies,
        offline=offline,
    )
    head_info = _resolve_side(
        head_root,
        python_lock=python_lock,
        go_module=go_module,
        go_list=go_list,
        java_dependencies=java_dependencies,
        offline=offline,
    )

    base_info["revision"], base_info["revision_exact"] = _git_revision(
        base_root, base_info.get("used_paths", ())
    )
    head_info["revision"], head_info["revision_exact"] = _git_revision(
        head_root, head_info.get("used_paths", ())
    )

    def verify_revision(info: dict[str, Any], supplied: str | None, label: str) -> None:
        if supplied is None:
            return
        actual = info.get("revision")
        if not actual:
            raise ProjectInputError(f"{label} revision cannot be verified because the checkout is not a Git worktree")
        if actual != supplied:
            raise ProjectInputError(f"{label} revision {supplied} does not match checked-out HEAD {actual}")
        if not info.get("revision_exact"):
            raise ProjectInputError(f"{label} checkout is dirty; supplied revision is not an exact source snapshot")

    verify_revision(base_info, base_revision, "baseline")
    verify_revision(head_info, head_revision, "candidate")
    base_languages = set(base_info["languages"])
    head_languages = set(head_info["languages"])
    if base_languages != head_languages:
        raise ProjectInputError(
            "baseline and candidate must expose the same supported languages: "
            f"baseline={sorted(base_languages)}, candidate={sorted(head_languages)}"
        )
    if "python" not in base_languages or not ({"go", "java"} & base_languages):
        raise ProjectInputError("project profile needs Python plus Go or Java")

    baseline = {
        language: details["resolved_version"] for language, details in base_info["languages"].items()
    }
    candidate = {
        language: details["resolved_version"] for language, details in head_info["languages"].items()
    }
    languages = [name for name in ("python", "go", "java") if name in base_languages]
    profile: dict[str, Any] = {
        "schema_version": 1,
        "name": "project-upgrade",
        "languages": languages,
        "baseline": baseline,
        "candidate": candidate,
        "source": "resolved-project",
    }
    if base_revision is not None:
        base_info["revision"] = base_revision
        base_info["revision_exact"] = bool(base_revision)
    if head_revision is not None:
        head_info["revision"] = head_revision
        head_info["revision_exact"] = bool(head_revision)
    metadata = {
        "schema_version": 1,
        "source": "resolved-project",
        "baseline": base_info,
        "candidate": head_info,
        "base_revision": base_info["revision"],
        "head_revision": head_info["revision"],
        "revisions": {"baseline": base_info["revision"], "candidate": head_info["revision"]},
        "manifest_hashes": {
            "baseline": [item["sha256"] for item in base_info["manifests"]],
            "candidate": [item["sha256"] for item in head_info["manifests"]],
        },
    }
    return profile, metadata


__all__ = ["ProjectInputError", "discover_languages", "project_languages", "resolve_project"]
