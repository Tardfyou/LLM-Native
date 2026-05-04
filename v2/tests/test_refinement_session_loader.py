import json
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core import Orchestrator
from src.core.analyzer_base import AnalyzerResult
from src.core.orchestrator import GenerationResult
from src.core.refinement_session import (
    EVIDENCE_INPUT_MANIFEST,
    REFINEMENT_INPUT_MANIFEST,
    RefinementSessionLoader,
)


def _sample_bundle():
    return {
        "records": [
            {
                "evidence_id": "patch_1",
                "type": "patch_fact",
                "analyzer": "patch",
                "scope": {"repo": "", "file": "src/demo.c", "function": "demo"},
                "location": {"line": 12, "column": 1},
                "semantic_payload": {
                    "fact_type": "affected_functions",
                    "label": "affected",
                    "attributes": {"functions": ["demo"]},
                },
                "provenance": {},
                "evidence_slice": {},
            }
        ],
        "missing_evidence": [],
        "collected_analyzers": ["csa"],
    }


class RefinementSessionLoaderTests(unittest.TestCase):
    def test_loader_auto_uses_evidence_manifest_from_input_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            generate_dir = root / "generate"
            csa_dir = generate_dir / "csa"
            csa_dir.mkdir(parents=True)

            patch_path = root / "demo.patch"
            patch_path.write_text("diff --git a/src/demo.c b/src/demo.c\n", encoding="utf-8")
            validate_dir = root / "validate"
            validate_dir.mkdir()
            evidence_source_dir = root / "project"
            evidence_source_dir.mkdir()

            checker_path = csa_dir / "DemoChecker.cpp"
            checker_path.write_text("int demo(void) { return 0; }\n", encoding="utf-8")
            result_path = csa_dir / "result.json"
            result_path.write_text(
                json.dumps({"checker_name": "DemoChecker"}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            refinement_input = {
                "schema_version": 1,
                "patch_path": str(patch_path),
                "validate_path": str(validate_dir),
                "analyzer_choice": "csa",
                "artifacts": {
                    "csa": {
                        "checker_name": "DemoChecker",
                        "source_path": "csa/DemoChecker.cpp",
                        "result_path": "csa/result.json",
                    }
                },
            }
            (generate_dir / REFINEMENT_INPUT_MANIFEST).write_text(
                json.dumps(refinement_input, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            (generate_dir / "patchweaver_plan.json").write_text(
                json.dumps({"patchweaver": {"summary": "generate"}}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (generate_dir / "final_report.json").write_text(
                json.dumps({"meta": {}}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            evidence_bundle_path = csa_dir / "evidence_bundle.json"
            evidence_bundle_path.write_text(
                json.dumps(_sample_bundle(), ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            evidence_manifest = {
                "schema_version": 1,
                "patch_path": str(patch_path),
                "evidence_dir": str(evidence_source_dir),
                "shared_analysis_path": "patchweaver_plan.json",
                "artifacts": {
                    "csa": {
                        "evidence_bundle_path": "csa/evidence_bundle.json",
                    }
                },
            }
            (generate_dir / EVIDENCE_INPUT_MANIFEST).write_text(
                json.dumps(evidence_manifest, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (generate_dir / "patchweaver_plan.json").write_text(
                json.dumps({"patchweaver": {"summary": "from_evidence"}}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            session = RefinementSessionLoader().load(input_dir=str(generate_dir))

            self.assertEqual(session.evidence_input_dir, str(generate_dir.resolve()))
            self.assertEqual(session.evidence_dir, str(evidence_source_dir.resolve()))
            self.assertEqual(session.shared_analysis["patchweaver"]["summary"], "from_evidence")
            self.assertEqual(
                session.artifacts["csa"].evidence_bundle_raw["records"][0]["evidence_id"],
                "patch_1",
            )

    def test_loader_rejects_mismatched_external_evidence_patch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            generate_dir = root / "generate"
            csa_dir = generate_dir / "csa"
            csa_dir.mkdir(parents=True)

            patch_path = root / "demo.patch"
            patch_path.write_text("diff --git a/src/demo.c b/src/demo.c\n", encoding="utf-8")
            other_patch = root / "other.patch"
            other_patch.write_text("diff --git a/src/other.c b/src/other.c\n", encoding="utf-8")

            checker_path = csa_dir / "DemoChecker.cpp"
            checker_path.write_text("int demo(void) { return 0; }\n", encoding="utf-8")
            result_path = csa_dir / "result.json"
            result_path.write_text("{}", encoding="utf-8")

            (generate_dir / REFINEMENT_INPUT_MANIFEST).write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "patch_path": str(patch_path),
                        "analyzer_choice": "csa",
                        "artifacts": {
                            "csa": {
                                "checker_name": "DemoChecker",
                                "source_path": "csa/DemoChecker.cpp",
                                "result_path": "csa/result.json",
                            }
                        },
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            (generate_dir / "final_report.json").write_text("{}", encoding="utf-8")

            evidence_dir = root / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / EVIDENCE_INPUT_MANIFEST).write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "patch_path": str(other_patch),
                        "artifacts": {},
                    },
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                RefinementSessionLoader().load(
                    input_dir=str(generate_dir),
                    evidence_input_dir=str(evidence_dir),
                )


class SaveResultEvidenceSeparationTests(unittest.TestCase):
    def test_save_result_omits_generate_stage_evidence_files_and_raw_fields(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            patch_path = root / "demo.patch"
            patch_path.write_text("diff --git a/src/demo.c b/src/demo.c\n", encoding="utf-8")

            orchestrator = Orchestrator()
            raw_bundle = _sample_bundle()
            analyzer_result = AnalyzerResult(
                analyzer_type="csa",
                success=True,
                checker_name="DemoChecker",
                checker_code="int demo(void) { return 0; }\n",
                metadata={
                    "validation_requested": False,
                    "artifact_review": {},
                    "evidence_bundle": raw_bundle,
                    "evidence_records": 1,
                    "missing_evidence": [],
                    "evidence_degraded": False,
                    "semantic_slice_records": 0,
                    "context_summary_records": 0,
                    "slice_coverage": "",
                    "verifier_backed_slices": 0,
                    "slice_kinds": {},
                    "evidence_escalation": {},
                    "evidence_summary": "summary",
                    "validation_feedback_records": 0,
                    "validation_feedback_summary": "",
                    "post_validation_evidence_records": 0,
                    "post_validation_missing_evidence": [],
                    "post_validation_semantic_slice_records": 0,
                    "post_validation_context_summary_records": 0,
                    "post_validation_slice_coverage": "",
                    "post_validation_evidence_summary": "",
                    "synthesis_input": {},
                },
            )
            report_entry = orchestrator._build_analyzer_report_entry(analyzer_result)
            self.assertNotIn("evidence_bundle", report_entry)
            self.assertNotIn("post_validation_evidence_bundle", report_entry)
            self.assertNotIn("validation_feedback_bundle", report_entry)
            self.assertNotIn("evidence_summary", report_entry)
            self.assertNotIn("post_validation_evidence_summary", report_entry)

            result = GenerationResult(
                workflow_mode="generate",
                patch_path=str(patch_path),
                analyzer_type="csa",
            )
            result.checker_name = "DemoChecker"
            result.analyzer_results["csa"] = report_entry
            result.analyzer_artifacts["csa"] = {
                "checker_code": "int demo(void) { return 0; }\n",
            }

            orchestrator.save_result(result, str(root / "output"))

            output_dir = root / "output"
            self.assertFalse((output_dir / "csa" / "evidence_bundle.json").exists())
            self.assertFalse((output_dir / "csa" / "post_validation_evidence_bundle.json").exists())

            refinement_input = json.loads((output_dir / REFINEMENT_INPUT_MANIFEST).read_text(encoding="utf-8"))
            artifact = refinement_input["artifacts"]["csa"]
            self.assertNotIn("evidence_bundle_path", artifact)
            self.assertNotIn("evidence_bundle_raw", artifact)
            self.assertNotIn("post_validation_evidence_bundle_path", artifact)
            self.assertNotIn("post_validation_evidence_bundle_raw", artifact)
            self.assertNotIn("evidence_summary", artifact["report_entry"])
            self.assertNotIn("post_validation_evidence_summary", artifact["report_entry"])

            saved_result = json.loads((output_dir / "csa" / "result.json").read_text(encoding="utf-8"))
            self.assertNotIn("evidence_bundle", saved_result)
            self.assertNotIn("post_validation_evidence_bundle", saved_result)
            self.assertNotIn("evidence_summary", saved_result)
            self.assertNotIn("post_validation_evidence_summary", saved_result)

            final_report = json.loads((output_dir / "final_report.json").read_text(encoding="utf-8"))
            self.assertNotIn("evidence_summary", final_report["csa"])
            self.assertNotIn("post_validation_evidence_summary", final_report["csa"])

            validation_feedback = json.loads((output_dir / "validation_feedback.json").read_text(encoding="utf-8"))
            self.assertNotIn("post_validation_evidence_summary", validation_feedback["csa"])
