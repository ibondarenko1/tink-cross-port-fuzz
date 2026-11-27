"""Command-line entry points for a release profile or two project checkouts."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from . import __version__
from . import check
from .project import resolve_project, stamp_export


def incomplete(output, revision, detail, project=None):
    """Persist errors that occur before a matrix can be constructed."""
    report = {
        "schema_version": 1, "status": "INCOMPLETE", "revision": revision,
        "summary": {"total": 1, "passed": 0, "failed": 0, "incomplete": 1},
        "rows": [{"id": "configuration", "scenario": "dependency resolution",
                  "producer": "n/a", "consumer": "n/a", "producer_phase": "", "consumer_phase": "",
                  "expected": "resolved inputs", "actual": "unavailable", "status": "INCOMPLETE",
                  "detail": str(detail)}],
        "profile": {}, "project": project, "runtimes": {}, "hashes": {}, "error": str(detail),
    }
    check.write_report(report, output)
    return report, 2


def run_resolved(profile, metadata, output, cache, offline, revision):
    with TemporaryDirectory(prefix="tink-compat-") as directory:
        path = Path(directory) / "profile.json"
        path.write_bytes((json.dumps(profile, sort_keys=True, indent=2) + "\n").encode())
        return check.run_check(path, check.DEFAULT_VECTORS, output, cache, offline, revision, project=metadata)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "check":
        return check.main(args)

    parser = argparse.ArgumentParser(prog="tink-compat", description="Check Tink upgrades against signed public fixtures.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check", help="run the bundled or an explicit release profile")
    stamp = commands.add_parser("stamp-export", help="bind a freshly resolved dependency export to its manifests")
    stamp.add_argument("--root", type=Path, default=Path.cwd())
    exports = stamp.add_mutually_exclusive_group(required=True)
    exports.add_argument("--go-list")
    exports.add_argument("--java-dependencies")
    stamp.add_argument("--go-module", help="Go module path inside the checkout")
    project = commands.add_parser("project", help="compare dependencies from two project checkouts")
    for name in ("base", "head", "out"):
        project.add_argument("--" + name, type=Path, required=True)
    for name in ("python-lock", "go-module", "go-list", "java-dependencies"):
        project.add_argument("--" + name, help="project-relative input path in each checkout")
    project.add_argument("--cache", type=Path, default=check._default_cache())
    project.add_argument("--offline", action="store_true", help="use prepared adapters and cached Go module metadata")
    project.add_argument("--revision", default=os.environ.get("TINK_COMPAT_REVISION", f"tink-release-compat@{__version__}"),
                        help="revision of the checker")
    args = parser.parse_args(args)
    if args.command == "stamp-export":
        try:
            print(stamp_export(args.root, go_list=args.go_list, go_module=args.go_module,
                               java_dependencies=args.java_dependencies))
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return 0
    opts = {key: getattr(args, key) for key in ("python_lock", "go_module", "go_list", "java_dependencies")}
    try:
        profile, metadata = resolve_project(args.base, args.head, **opts, offline=args.offline)
        report, code = run_resolved(profile, metadata, args.out, args.cache, args.offline, args.revision)
    except (ValueError, OSError) as exc:
        report, code = incomplete(args.out, args.revision, exc)
    print(f"Tink project compatibility: {report['status']} ({args.out / 'report.md'})")
    return code


if __name__ == "__main__":
    sys.exit(main())
