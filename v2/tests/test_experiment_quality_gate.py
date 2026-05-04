import csv
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.experiments.runner import audit_manifest, init_experiment_root, run_experiments


class ExperimentQualityGateTests(unittest.TestCase):
    def _write_manifest_row(self, manifest_path: Path, row):
        with manifest_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(row)

    def test_audit_marks_manual_review_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            layout = init_experiment_root(root=str(root))

            sample_root = root / "sample_case"
            vuln_dir = sample_root / "vuln" / "src"
            fixed_dir = sample_root / "fixed" / "src"
            vuln_dir.mkdir(parents=True, exist_ok=True)
            fixed_dir.mkdir(parents=True, exist_ok=True)

            patch_path = sample_root / "fix.patch"
            patch_path.write_text(
                "diff --git a/src/demo.c b/src/demo.c\n"
                "--- a/src/demo.c\n"
                "+++ b/src/demo.c\n"
                "@@ -1 +1 @@\n"
                "-int bug(void) { return 0; }\n"
                "+int fix(void) { return 1; }\n",
                encoding="utf-8",
            )
            (vuln_dir / "demo.c").write_text("int bug(void) { return 0; }\n", encoding="utf-8")
            (fixed_dir / "demo.c").write_text("int fix(void) { return 1; }\n", encoding="utf-8")

            self._write_manifest_row(
                layout.manifest_path,
                [
                    "sample-001",
                    "demo",
                    "CWE-787",
                    "buffer overflow",
                    str(patch_path),
                    str(sample_root / "vuln"),
                    str(sample_root / "fixed"),
                    str(sample_root / "vuln"),
                    "csa",
                    "true",
                    "false",
                    "false",
                    "draft",
                    "",
                    "",
                    "",
                    "",
                ],
            )

            audit_manifest(root=str(root))

            registry_path = layout.tables_dir / "sample_registry.csv"
            with registry_path.open("r", newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))

            self.assertEqual(row["sample_id"], "sample-001")
            self.assertEqual(row["manual_review_ok"], "false")
            self.assertEqual(row["run_eligible"], "false")
            self.assertIn("quality_status 不是 approved", row["review_requirements_missing"])
            self.assertIn("reviewer 未填写", row["review_requirements_missing"])

    def test_run_blocks_when_selected_samples_not_reviewed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            layout = init_experiment_root(root=str(root))

            sample_root = root / "sample_case"
            vuln_dir = sample_root / "vuln" / "src"
            fixed_dir = sample_root / "fixed" / "src"
            vuln_dir.mkdir(parents=True, exist_ok=True)
            fixed_dir.mkdir(parents=True, exist_ok=True)

            patch_path = sample_root / "fix.patch"
            patch_path.write_text(
                "diff --git a/src/demo.c b/src/demo.c\n"
                "--- a/src/demo.c\n"
                "+++ b/src/demo.c\n"
                "@@ -1 +1 @@\n"
                "-int bug(void) { return 0; }\n"
                "+int fix(void) { return 1; }\n",
                encoding="utf-8",
            )
            (vuln_dir / "demo.c").write_text("int bug(void) { return 0; }\n", encoding="utf-8")
            (fixed_dir / "demo.c").write_text("int fix(void) { return 1; }\n", encoding="utf-8")

            self._write_manifest_row(
                layout.manifest_path,
                [
                    "sample-002",
                    "demo",
                    "CWE-787",
                    "buffer overflow",
                    str(patch_path),
                    str(sample_root / "vuln"),
                    str(sample_root / "fixed"),
                    str(sample_root / "vuln"),
                    "csa",
                    "true",
                    "false",
                    "false",
                    "approved",
                    "",
                    "",
                    "",
                    "",
                ],
            )

            with self.assertRaisesRegex(ValueError, "选中样本未全部通过审查"):
                run_experiments(root=str(root), run_all=True)


if __name__ == "__main__":
    unittest.main()
