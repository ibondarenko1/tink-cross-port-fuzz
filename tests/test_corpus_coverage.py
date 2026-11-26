import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from harnesses.py import differential


class CorpusCoverageTests(unittest.TestCase):
    def replay(self, verdicts, empty=False):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root = Path(tmp)
            corpus = root / "corpus"
            corpus.mkdir()
            if not empty:
                known_good = differential.REPO_ROOT / "corpus_jwk/16_valid_es256_baseline.json"
                (corpus / "sample.json").write_bytes(known_good.read_bytes())
            for adapter, status in zip(("py", "go", "java", "cc"), verdicts):
                name = "python" if adapter == "py" else adapter
                stack.enter_context(patch.object(differential, "run_" + name,
                                                 return_value=differential.Outcome(adapter, status)))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            out = root / "out"
            code = differential.main([str(corpus), "--report-dir", str(out)])
            return code, json.loads((out / "summary.json").read_bytes())

    def test_only_reads_agreement_from_real_decisions(self):
        for py, go, code, status in [
            ("UNAVAILABLE", "UNAVAILABLE", 2, "INCOMPLETE"),
            ("ACCEPT", "UNAVAILABLE", 2, "INCOMPLETE"),
            ("ACCEPT", "TIMEOUT", 2, "INCOMPLETE"),
            ("ACCEPT", "RUNNER_ERROR", 2, "INCOMPLETE"),
            ("ACCEPT", "REJECT_TINK", 1, "DIVERGENCE"),
            ("ACCEPT", "ACCEPT", 0, "AGREE"),
        ]:
            with self.subTest(python=py, go=go):
                rc, report = self.replay((py, go, "UNAVAILABLE", "UNAVAILABLE"))
                self.assertEqual((rc, report["status"]), (code, status))
                self.assertEqual(report["inputs"][0]["status"], status)

    def test_empty_corpus_cannot_pass(self):
        rc, report = self.replay(("ACCEPT", "ACCEPT", "UNAVAILABLE", "UNAVAILABLE"), empty=True)
        self.assertEqual((rc, report["status"]), (2, "INCOMPLETE"))
