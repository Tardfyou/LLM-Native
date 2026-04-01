import json
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT_ROOT / "src" / "core" / "refinement_session.py"
SPEC = importlib.util.spec_from_file_location("v2_refinement_session", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
REFINEMENT_SESSION_MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REFINEMENT_SESSION_MODULE
SPEC.loader.exec_module(REFINEMENT_SESSION_MODULE)

REFINEMENT_INPUT_MANIFEST = REFINEMENT_SESSION_MODULE.REFINEMENT_INPUT_MANIFEST
RefinementSessionLoader = REFINEMENT_SESSION_MODULE.RefinementSessionLoader


class RefinementSessionLoaderTests(unittest.TestCase):
    def setUp(self):
        self.loader = RefinementSessionLoader()

    def _write_json(self, path: Path, payload):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def test_loader_prefers_refinement_manifest_and_resolves_relative_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            patch_path = root / "buffer.patch"
            validate_path = root / "fixture_project"
            validate_path.mkdir()
            patch_path.write_text("diff --git a/x b/x\n", encoding="utf-8")

            csa_dir = root / "csa"
            source_path = csa_dir / "BufferChecker.cpp"
            output_path = csa_dir / "BufferChecker.so"
            evidence_path = csa_dir / "evidence_bundle.json"
            post_evidence_path = csa_dir / "post_validation_evidence_bundle.json"
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text("class BufferChecker {};\n", encoding="utf-8")
            output_path.write_bytes(b"\x7fELF")
            self._write_json(evidence_path, {"records": [{"id": "pre"}]})
            self._write_json(post_evidence_path, {"records": [{"id": "post"}]})
            self._write_json(
                csa_dir / "result.json",
                {
                    "checker_name": "BufferChecker",
                    "output_path": str(output_path),
                    "validation_feedback_summary": "manifest-summary",
                },
            )
            self._write_json(root / "patchweaver_plan.json", {"patchweaver": {"summary": "from-manifest"}})

            self._write_json(
                root / "final_report.json",
                {
                    "meta": {
                        "patch_path": "wrong.patch",
                        "validate_path": "wrong-validate",
                        "analyzer_type": "codeql",
                    },
                    "codeql": {
                        "checker_name": "WrongQuery",
                    },
                },
            )
            self._write_json(
                root / REFINEMENT_INPUT_MANIFEST,
                {
                    "schema_version": 1,
                    "workflow_mode": "generate",
                    "patch_path": "buffer.patch",
                    "validate_path": "fixture_project",
                    "analyzer_choice": "csa",
                    "shared_analysis_path": "patchweaver_plan.json",
                    "artifacts": {
                        "csa": {
                            "checker_name": "BufferChecker",
                            "source_path": "csa/BufferChecker.cpp",
                            "output_path": "csa/BufferChecker.so",
                            "result_path": "csa/result.json",
                            "evidence_bundle_path": "csa/evidence_bundle.json",
                            "post_validation_evidence_bundle_path": "csa/post_validation_evidence_bundle.json",
                        }
                    },
                },
            )

            session = self.loader.load(str(root))

            self.assertEqual(session.patch_path, str(patch_path.resolve()))
            self.assertEqual(session.validate_path, str(validate_path.resolve()))
            self.assertEqual(session.analyzer_choice, "csa")
            self.assertEqual(session.shared_analysis["patchweaver"]["summary"], "from-manifest")
            self.assertIn("csa", session.artifacts)
            artifact = session.artifacts["csa"]
            self.assertEqual(artifact.source_path, str(source_path.resolve()))
            self.assertEqual(artifact.output_path, str(output_path.resolve()))
            self.assertEqual(artifact.report_entry["checker_name"], "BufferChecker")
            self.assertEqual(artifact.report_entry["validation_feedback_summary"], "manifest-summary")
            self.assertEqual(artifact.post_validation_evidence_bundle_raw["records"][0]["id"], "post")

    def test_loader_falls_back_to_legacy_report_when_manifest_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            patch_path = root / "legacy.patch"
            validate_path = root / "legacy_project"
            validate_path.mkdir()
            patch_path.write_text("diff --git a/y b/y\n", encoding="utf-8")

            csa_dir = root / "csa"
            source_path = csa_dir / "LegacyChecker.cpp"
            output_path = csa_dir / "LegacyChecker.so"
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_text("class LegacyChecker {};\n", encoding="utf-8")
            output_path.write_bytes(b"\x7fELF")
            self._write_json(root / "patchweaver_plan.json", {"patchweaver": {"summary": "legacy-plan"}})
            self._write_json(
                root / "final_report.json",
                {
                    "meta": {
                        "patch_path": str(patch_path),
                        "validate_path": str(validate_path),
                        "analyzer_type": "csa",
                    },
                    "csa": {
                        "checker_name": "LegacyChecker",
                        "output_path": str(output_path),
                        "validation_feedback_summary": "legacy-summary",
                    },
                },
            )
            self._write_json(csa_dir / "evidence_bundle.json", {"records": [{"id": "legacy"}]})

            session = self.loader.load(str(root))

            self.assertEqual(session.patch_path, str(patch_path.resolve()))
            self.assertEqual(session.validate_path, str(validate_path.resolve()))
            self.assertEqual(session.shared_analysis["patchweaver"]["summary"], "legacy-plan")
            self.assertIn("csa", session.artifacts)
            artifact = session.artifacts["csa"]
            self.assertEqual(artifact.checker_name, "LegacyChecker")
            self.assertEqual(artifact.source_path, str(source_path.resolve()))
            self.assertEqual(artifact.checker_code, "class LegacyChecker {};\n")
            self.assertEqual(artifact.evidence_bundle_raw["records"][0]["id"], "legacy")


if __name__ == "__main__":
    unittest.main()
