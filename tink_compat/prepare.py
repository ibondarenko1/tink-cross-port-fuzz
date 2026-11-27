"""Prepare pinned Tink runners for the compatibility command.

The compatibility command calls this module for every language/version in its
profile.  Preparation is deliberately boring and local: each artifact lives
under the caller-provided cache, lock directories serialize concurrent setup,
and a failed build never replaces an already usable artifact.
"""

from __future__ import annotations

import json
import hashlib
import os
import platform
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import venv

if os.name == "nt":
    import msvcrt
else:
    import fcntl


LOCK_TIMEOUT_SECONDS = 900
SUPPORTED: dict[str, set[str]]


class PrepareError(RuntimeError):
    """A runner could not be prepared with the requested pinned version."""


def _project_root() -> Path:
    package_root = Path(__file__).resolve().parent
    source_root = package_root.parent
    if (source_root / "runners").is_dir():
        return source_root
    # Wheels keep native sources under ``tink_compat/_bundled`` while Python
    # lock files remain next to this module.
    return package_root


def _catalog_path(project_root: Path) -> Path:
    candidates = (
        project_root / "tink_compat" / "data" / "catalog.json",
        project_root / "data" / "catalog.json",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise PrepareError("Tink release catalog is missing")


def _catalog(project_root: Path) -> dict:
    try:
        value = json.loads(_catalog_path(project_root).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PrepareError("Tink release catalog is unreadable") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise PrepareError("Tink release catalog has an unsupported schema")
    languages = value.get("languages")
    if not isinstance(languages, dict):
        raise PrepareError("Tink release catalog has no languages")
    return value


def _catalog_record(project_root: Path, language: str, version: str) -> dict:
    languages = _catalog(project_root)["languages"]
    language_record = languages.get(language)
    if not isinstance(language_record, dict):
        raise PrepareError(f"catalog has no {language} adapter")
    versions = language_record.get("versions")
    if not isinstance(versions, dict) or not isinstance(versions.get(version), dict):
        raise PrepareError(f"catalog has no {language} version {version}")
    return dict(versions[version])


def _catalog_supported(project_root: Path) -> dict[str, set[str]]:
    languages = _catalog(project_root)["languages"]
    supported: dict[str, set[str]] = {}
    for language, language_record in languages.items():
        if not isinstance(language, str) or not isinstance(language_record, dict):
            continue
        versions = language_record.get("versions")
        if not isinstance(versions, dict):
            continue
        supported[language] = {str(version) for version in versions}
    return supported


SUPPORTED = _catalog_supported(_project_root())


def _toolchain_fingerprint(language: str) -> bytes:
    """Return stable runner/platform identity for an adapter cache key."""
    identity = [platform.system(), platform.machine(), platform.python_implementation()]
    if language == "python":
        identity.append(platform.python_version())
    else:
        executables = (("go", ["version"]),) if language == "go" else (
            ("java", ["-version"]),
            ("mvn", ["-version"]),
        )
        for executable, command_suffix in executables:
            found = shutil.which(executable) or "missing"
            identity.append(f"{executable}:{found}")
            if found == "missing":
                identity.append("unavailable")
                continue
            try:
                result = subprocess.run(
                    [found, *command_suffix], capture_output=True, text=True, timeout=10, check=False
                )
                identity.append((result.stdout or result.stderr).strip())
            except (OSError, subprocess.TimeoutExpired):
                identity.append("unavailable")
    return "\0".join(identity).encode("utf-8")


def _adapter_inputs(project_root: Path, language: str, version: str) -> list[tuple[str, Path]]:
    inputs: list[tuple[str, Path]] = []
    if language == "python":
        adapter = project_root / "adapters" / "python_adapter.py"
        if not adapter.is_file():
            adapter = project_root / "tink_compat" / "adapters" / "python_adapter.py"
        inputs.extend(
            [
                ("python-lock", _python_lock(project_root, version)),
                ("python-adapter", adapter),
            ]
        )
    elif language == "go":
        source = _go_source(project_root)
        lock = _go_lock(project_root, version)
        inputs.extend(
            [
                ("go-source", source),
                ("go-mod", lock / "go.mod"),
                ("go-sum", lock / "go.sum"),
            ]
        )
    else:
        source = project_root / "runners" / "java-runner"
        if not source.is_dir():
            source = project_root / "_bundled" / "java-runner"
        inputs.extend(
            [
                ("java-pom", source / "pom.xml"),
                ("java-source", source / "src" / "main"),
            ]
        )
    return inputs


def adapter_fingerprint(language: str, version: str) -> str:
    """Hash the exact catalog, source, lock and local toolchain inputs.

    Actions may use this value as a per-language/version cache suffix.  The
    same helper is used by preparation, so a source or lock change cannot
    accidentally reuse an old native artifact.
    """
    language = language.strip().lower()
    version = version.strip().lstrip("v")
    if language not in SUPPORTED or version not in SUPPORTED[language]:
        raise PrepareError(f"unsupported adapter {language}@{version}")
    root = _project_root()
    digest = hashlib.sha256()
    digest.update(f"{language}\0{version}\0".encode("utf-8"))
    digest.update(_toolchain_fingerprint(language))
    digest.update(
        json.dumps(_catalog_record(root, language, version), sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    digest.update(_fingerprint(_adapter_inputs(root, language, version)).encode("ascii"))
    return digest.hexdigest()


def _lock_dir(cache: Path, language: str, version: str) -> Path:
    safe = f"{language}-{version}".replace("/", "_")
    return cache / ".locks" / f"{safe}.lock"


class _CacheLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = None
        self.acquired = False

    def __enter__(self) -> "_CacheLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+b")
        if os.name == "nt":
            # msvcrt.locking works on a byte range beginning at the current
            # file pointer.  Ensure that byte exists before seeking to it.
            self.handle.seek(0, os.SEEK_END)
            if self.handle.tell() == 0:
                self.handle.write(b"\0")
                self.handle.flush()
            self.handle.seek(0)
        started = time.monotonic()
        while True:
            try:
                if os.name == "nt":
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.acquired = True
                return self
            except OSError:
                if time.monotonic() - started > LOCK_TIMEOUT_SECONDS:
                    self.handle.close()
                    self.handle = None
                    raise PrepareError(f"timed out waiting for cache lock {self.path}")
                time.sleep(0.25)

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.handle is None:
            return
        try:
            if self.acquired:
                if os.name == "nt":
                    self.handle.seek(0)
                    msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        finally:
            self.handle.close()
            self.handle = None
            self.acquired = False


def _run(command: list[str], *, cwd: Path | None = None, offline: bool = False) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")
    env.setdefault("GOTOOLCHAIN", "local")
    if offline:
        env["PIP_NO_INDEX"] = "1"
    try:
        return subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=1800,
        )
    except FileNotFoundError as exc:
        raise PrepareError(f"required executable is unavailable: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise PrepareError(f"command timed out after 1800 seconds: {' '.join(command)}") from exc


def _failure(label: str, result: subprocess.CompletedProcess[str]) -> PrepareError:
    details = (result.stderr or result.stdout or "").strip().splitlines()
    detail = details[-1] if details else f"exit code {result.returncode}"
    return PrepareError(f"{label} failed: {detail[:500]}")


def _fingerprint(items: list[tuple[str, Path]]) -> str:
    """Hash the exact source and lock inputs used to build an artifact.

    The cache is shared between runs and may outlive a checkout.  A version
    directory alone is therefore not a sufficient cache key: changing a
    runner source file or a lock file must force a fresh native build.  File
    names are included as well as bytes so additions and removals are visible
    to the digest.
    """

    digest = hashlib.sha256()
    for label, root in sorted(items, key=lambda item: item[0]):
        if root.is_dir():
            files = sorted(
                path
                for path in root.rglob("*")
                if path.is_file()
                and not any(part in {".git", "target", "__pycache__"} for part in path.relative_to(root).parts)
            )
            if not files:
                raise PrepareError(f"cache input directory is empty: {root}")
            for path in files:
                relative = path.relative_to(root).as_posix()
                digest.update(f"{label}/{relative}\0".encode("utf-8"))
                try:
                    digest.update(path.read_bytes())
                except OSError as exc:
                    raise PrepareError(f"cannot read cache input {path}: {exc}") from exc
        elif root.is_file():
            digest.update(f"{label}/{root.name}\0".encode("utf-8"))
            try:
                digest.update(root.read_bytes())
            except OSError as exc:
                raise PrepareError(f"cannot read cache input {root}: {exc}") from exc
        else:
            raise PrepareError(f"cache input is missing: {root}")
    return digest.hexdigest()


def _manifest_path(target: Path) -> Path:
    return target / ".manifest.json"


def _manifest_matches(target: Path, fingerprint: str) -> bool:
    manifest = _manifest_path(target)
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(value, dict) and value.get("schema_version") == 1 and value.get("fingerprint") == fingerprint


def _write_manifest(target: Path, fingerprint: str) -> None:
    temporary = _manifest_path(target).with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"schema_version": 1, "fingerprint": fingerprint}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(_manifest_path(target))


def _python_executable(venv_dir: Path) -> Path:
    return venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _python_lock(project_root: Path, version: str) -> Path:
    lock_root = project_root / "tink_compat" if (project_root / "tink_compat").is_dir() else project_root
    lock = lock_root / "locks" / "python" / version / "requirements.txt"
    if not lock.is_file():
        raise PrepareError(f"Python lock file is missing: {lock}")
    return lock


def _prepare_python(project_root: Path, cache: Path, version: str, offline: bool) -> list[str]:
    target = cache / "python" / version
    venv_dir = target / "venv"
    executable = _python_executable(venv_dir)
    lock = _python_lock(project_root, version)
    fingerprint = adapter_fingerprint("python", version)
    adapter = project_root / "adapters" / "python_adapter.py"
    if not adapter.is_file():
        adapter = project_root / "tink_compat" / "adapters" / "python_adapter.py"
    if not adapter.is_file():
        raise PrepareError(f"Python compatibility adapter is missing: {adapter}")
    with _CacheLock(_lock_dir(cache, "python", version)):
        ready = executable.is_file() and _manifest_matches(target, fingerprint)
        if not ready:
            if offline:
                raise PrepareError(
                    f"cached Python {version} runner is missing or stale for the current lock at {target}"
                )
            if venv_dir.exists():
                shutil.rmtree(venv_dir)
            target.mkdir(parents=True, exist_ok=True)
            builder = venv.EnvBuilder(with_pip=True, clear=False, symlinks=(os.name != "nt"))
            builder.create(venv_dir)
        check = _run(
            [str(executable), "-c", "import importlib.metadata as m; print(m.version('tink'))"],
            offline=offline,
        )
        installed = check.stdout.strip() if check.returncode == 0 else ""
        if installed != version:
            if offline:
                raise PrepareError(f"Tink Python {version} is not installed in {venv_dir} and offline mode is enabled")
            result = _run([str(executable), "-m", "pip", "install", "--no-input", "--requirement", str(lock)])
            if result.returncode != 0:
                raise _failure(f"installing Tink Python {version}", result)
        if not _manifest_matches(target, fingerprint):
            _write_manifest(target, fingerprint)
    # The adapter is standalone and has no package-relative imports.  Isolated
    # mode prevents a consumer's PYTHONPATH or checkout from shadowing the
    # managed venv's pinned Tink installation.
    return [str(executable), "-I", str(adapter)]


def _go_lock(project_root: Path, version: str) -> Path:
    if version == "2.4.0":
        lock = project_root / "runners" / "go-runner"
        if not lock.is_dir():
            lock = project_root / "_bundled" / "go-runner"
    else:
        lock = project_root / "tink_compat" / "locks" / "go" / version
        if not lock.is_dir():
            lock = project_root / "locks" / "go" / version
    if not (lock / "go.mod").is_file():
        raise PrepareError(f"Go lock file is missing: {lock / 'go.mod'}")
    return lock


def _go_source(project_root: Path) -> Path:
    source = project_root / "runners" / "go-runner"
    if not source.is_dir():
        source = project_root / "_bundled" / "go-runner"
    compat = source / "cmd" / "compat"
    if compat.is_dir():
        return compat
    raise PrepareError(f"Go compatibility runner is missing: {compat}")


def _prepare_go(project_root: Path, cache: Path, version: str, offline: bool) -> list[str]:
    target = cache / "go" / version
    binary = target / ("compat.exe" if os.name == "nt" else "compat")
    source = _go_source(project_root)
    lock = _go_lock(project_root, version)
    fingerprint = adapter_fingerprint("go", version)
    with _CacheLock(_lock_dir(cache, "go", version)):
        ready = binary.is_file() and _manifest_matches(target, fingerprint)
        if not ready:
            if offline:
                raise PrepareError(f"Go compatibility runner {version} is missing or stale at {binary}")
            go = shutil.which("go")
            if not go:
                raise PrepareError("Go is required to build the compatibility runner")
            target.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=f"source-{version}-", dir=target))
            temporary_binary: Path | None = None
            try:
                shutil.copytree(source, staging, dirs_exist_ok=True)
                for name in ("go.mod", "go.sum"):
                    lock_file = lock / name
                    if lock_file.is_file():
                        shutil.copy2(lock_file, staging / name)
                download = _run([go, "mod", "download"], cwd=staging)
                if download.returncode != 0:
                    raise _failure(f"resolving Go {version} dependencies", download)
                fd, temporary_name = tempfile.mkstemp(
                    prefix="compat-", suffix=".exe" if os.name == "nt" else ".tmp", dir=target
                )
                os.close(fd)
                temporary_binary = Path(temporary_name)
                temporary_binary.unlink()
                result = _run([go, "build", "-mod=readonly", "-o", str(temporary_binary), "."], cwd=staging)
                if result.returncode != 0:
                    raise _failure(f"building Go {version} compatibility runner", result)
                temporary_binary.replace(binary)
                temporary_binary = None
                if os.name != "nt":
                    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
                _write_manifest(target, fingerprint)
                # Older releases used a persistent source copy.  Native source
                # is now disposable staging and should not inflate the cache.
                shutil.rmtree(target / "source", ignore_errors=True)
            finally:
                if temporary_binary is not None:
                    temporary_binary.unlink(missing_ok=True)
                shutil.rmtree(staging, ignore_errors=True)
    return [str(binary)]


def _prepare_java(project_root: Path, cache: Path, version: str, offline: bool) -> list[str]:
    target = cache / "java" / version
    jar = target / "target" / "tink-cross-port-java-runner-0.1.0.jar"
    java = shutil.which("java")
    if not java:
        raise PrepareError("Java is required to run the compatibility runner")
    source = project_root / "runners" / "java-runner"
    if not source.is_dir():
        source = project_root / "_bundled" / "java-runner"
    pom = source / "pom.xml"
    java_sources = source / "src" / "main"
    java_record = _catalog_record(project_root, "java", version)
    protobuf_version = java_record.get("protobuf")
    if not isinstance(protobuf_version, str) or not protobuf_version:
        raise PrepareError(f"catalog Java {version} entry has no protobuf version")
    fingerprint = adapter_fingerprint("java", version)
    with _CacheLock(_lock_dir(cache, "java", version)):
        ready = jar.is_file() and _manifest_matches(target, fingerprint)
        if not ready:
            if offline:
                raise PrepareError(f"Java compatibility runner {version} is missing or stale at {jar}")
            if not pom.is_file() or not java_sources.is_dir():
                raise PrepareError(f"Java runner source is missing: {source}")
            target.mkdir(parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=f"source-{version}-", dir=target))
            temporary_jar: Path | None = None
            try:
                build = staging
                shutil.copy2(pom, build / "pom.xml")
                shutil.copytree(java_sources, build / "src" / "main")
                mvn = shutil.which("mvn") or shutil.which("mvn.cmd")
                if not mvn:
                    raise PrepareError("Maven is required to build the Java compatibility runner")
                args = [
                    mvn,
                    "-B",
                    "-ntp",
                    f"-Dtink.version={version}",
                    f"-Dprotobuf.version={protobuf_version}",
                    "-DskipTests",
                    "-DcreateDependencyReducedPom=false",
                    "package",
                ]
                if offline:
                    args.insert(3, "-o")
                result = _run(args, cwd=build, offline=offline)
                if result.returncode != 0:
                    raise _failure(f"building Java {version} compatibility runner", result)
                built = build / "target" / jar.name
                if not built.is_file():
                    raise PrepareError(f"Maven completed without producing {jar.name}")
                jar.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary_name = tempfile.mkstemp(prefix="tink-java-", suffix=".jar", dir=jar.parent)
                os.close(fd)
                temporary_jar = Path(temporary_name)
                shutil.copy2(built, temporary_jar)
                temporary_jar.replace(jar)
                temporary_jar = None
                _write_manifest(target, fingerprint)
                shutil.rmtree(target / "source", ignore_errors=True)
            finally:
                if temporary_jar is not None:
                    temporary_jar.unlink(missing_ok=True)
                shutil.rmtree(staging, ignore_errors=True)
    return [java, "-jar", str(jar), "--compat"]


def prepare(language: str, version: str, cache: Path, *, offline: bool = False) -> list[str]:
    """Return an executable argv for one pinned compatibility adapter."""
    language = language.strip().lower()
    version = version.strip().lstrip("v")
    if language not in SUPPORTED:
        raise PrepareError(f"unsupported language {language!r}; choose one of {sorted(SUPPORTED)}")
    if version not in SUPPORTED[language]:
        raise PrepareError(f"unsupported {language} version {version!r}; choose one of {sorted(SUPPORTED[language])}")
    cache = Path(cache).expanduser().resolve()
    cache.mkdir(parents=True, exist_ok=True)
    root = _project_root()
    if language == "python":
        return _prepare_python(root, cache, version, offline)
    if language == "go":
        return _prepare_go(root, cache, version, offline)
    return _prepare_java(root, cache, version, offline)


__all__ = ["PrepareError", "SUPPORTED", "adapter_fingerprint", "prepare"]
