import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.tools.apply_patch import ApplyPatchTool
import src.tools.apply_patch as apply_patch_module


class ApplyPatchToolTests(unittest.TestCase):
    def test_accepts_close_resulting_content_fallback(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "sample.cpp"
            target.write_text("int value() {\n  return 0;\n}\n", encoding="utf-8")

            tool = ApplyPatchTool(work_dir=str(root), save_versions=False)
            result = tool.execute(
                target_path=str(target),
                source_path=str(target),
                patch=(
                    "--- a/sample.cpp\n"
                    "+++ b/sample.cpp\n"
                    "@@ -1,3 +1,3 @@\n"
                    "-int wrong() {\n"
                    "+int wrong() {\n"
                    "   return 0;\n"
                    " }\n"
                ),
                resulting_content="int value() {\n  return 1;\n}\n",
            )

            self.assertTrue(result.success, result.error)
            self.assertEqual(target.read_text(encoding="utf-8"), "int value() {\n  return 1;\n}\n")

    def test_rejects_resulting_content_that_rewrites_far_more_than_patch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "sample.cpp"
            target.write_text(
                "int keep_one() {\n  return 1;\n}\n\nint keep_two() {\n  return 2;\n}\n",
                encoding="utf-8",
            )

            tool = ApplyPatchTool(work_dir=str(root), save_versions=False)
            result = tool.execute(
                target_path=str(target),
                source_path=str(target),
                patch=(
                    "--- a/sample.cpp\n"
                    "+++ b/sample.cpp\n"
                    "@@ -1,3 +1,3 @@\n"
                    "-int missing_context() {\n"
                    "+int missing_context() {\n"
                    "   return 1;\n"
                    " }\n"
                ),
                resulting_content="".join(
                    f"int rewritten_{index}() {{\n  return {index};\n}}\n"
                    for index in range(40)
                ),
            )

            self.assertFalse(result.success)
            self.assertIn("resulting_content", result.error or "")
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "int keep_one() {\n  return 1;\n}\n\nint keep_two() {\n  return 2;\n}\n",
            )

    def test_rejects_ambiguous_relocated_hunk(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            target = root / "sample.cpp"
            target.write_text(
                "void keep_a() {\n"
                "  int value = 0;\n"
                "}\n\n"
                "void keep_b() {\n"
                "  int value = 0;\n"
                "}\n",
                encoding="utf-8",
            )

            tool = ApplyPatchTool(work_dir=str(root), save_versions=False)
            with mock.patch.object(apply_patch_module, "patch_ng", None):
                result = tool.execute(
                    target_path=str(target),
                    source_path=str(target),
                    patch=(
                        "--- a/sample.cpp\n"
                        "+++ b/sample.cpp\n"
                        "@@ -20,3 +20,3 @@\n"
                        "   int value = 0;\n"
                        "-}\n"
                        "+  return;\n"
                    ),
                )

            self.assertFalse(result.success)
            self.assertIn("多个完全匹配位置", result.error or "")
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "void keep_a() {\n"
                "  int value = 0;\n"
                "}\n\n"
                "void keep_b() {\n"
                "  int value = 0;\n"
                "}\n",
            )


if __name__ == "__main__":
    unittest.main()
