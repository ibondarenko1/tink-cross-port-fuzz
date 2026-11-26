import json
import copy
from pathlib import Path
import subprocess

import tink_compat.prepare as prepare_module
from tink_compat.prepare import SUPPORTED, adapter_fingerprint


ROOT = Path(__file__).parents[1]


def test_catalog_retains_historical_and_current_releases():
    catalog = json.loads((ROOT / "tink_compat" / "data" / "catalog.json").read_text(encoding="utf-8"))
    assert catalog["schema_version"] == 1
    assert {"1.14.1", "1.15.0", "1.16.1"} <= set(catalog["languages"]["python"]["versions"])
    assert {"2.4.0", "2.5.0", "2.9.0"} <= set(catalog["languages"]["go"]["versions"])
    assert {"1.18.0", "1.24.0"} <= set(catalog["languages"]["java"]["versions"])
    assert SUPPORTED["python"] >= {"1.14.1", "1.15.0", "1.16.1"}
    assert SUPPORTED["go"] >= {"2.4.0", "2.5.0", "2.9.0"}
    assert SUPPORTED["java"] >= {"1.18.0", "1.24.0"}


def test_adapter_fingerprint_is_version_and_source_specific():
    current = adapter_fingerprint("python", "1.16.1")
    historical = adapter_fingerprint("python", "1.15.0")
    assert len(current) == 64
    assert current != historical


def test_catalog_fingerprint_is_scoped_to_selected_adapter(monkeypatch):
    original = prepare_module._catalog
    baseline = adapter_fingerprint("python", "1.16.1")

    def changed_go(root):
        catalog = copy.deepcopy(original(root))
        catalog["languages"]["go"]["versions"]["2.9.0"]["release"] = "changed"
        return catalog

    monkeypatch.setattr(prepare_module, "_catalog", changed_go)
    assert adapter_fingerprint("python", "1.16.1") == baseline


def test_java_dependency_recipe_is_part_of_fingerprint(monkeypatch):
    original = prepare_module._catalog
    baseline = adapter_fingerprint("java", "1.24.0")

    def changed_java(root):
        catalog = copy.deepcopy(original(root))
        catalog["languages"]["java"]["versions"]["1.24.0"]["protobuf"] = "changed"
        return catalog

    monkeypatch.setattr(prepare_module, "_catalog", changed_java)
    assert adapter_fingerprint("java", "1.24.0") != baseline


def test_failed_go_rebuild_keeps_known_good_binary(monkeypatch, tmp_path):
    target = tmp_path / "go" / "2.9.0"
    target.mkdir(parents=True)
    binary = target / "compat"
    original_bytes = b"known-good-runner"
    binary.write_bytes(original_bytes)
    (target / ".manifest.json").write_text(
        '{"schema_version": 1, "fingerprint": "stale"}\n', encoding="utf-8"
    )

    monkeypatch.setattr(prepare_module.shutil, "which", lambda name: "/usr/bin/go" if name == "go" else None)
    monkeypatch.setattr(
        prepare_module,
        "_run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 1, "", "synthetic build failure"),
    )
    try:
        prepare_module._prepare_go(ROOT, tmp_path, "2.9.0", False)
    except prepare_module.PrepareError as exc:
        assert "Go 2.9.0" in str(exc)
    else:
        raise AssertionError("expected the synthetic Go build to fail")
    assert binary.read_bytes() == original_bytes
    assert not (target / "source").exists()
