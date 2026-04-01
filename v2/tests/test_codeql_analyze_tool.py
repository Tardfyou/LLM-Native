import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.tools.codeql_analyze import CodeQLAnalyzeTool


class CodeQLAnalyzeToolTests(unittest.TestCase):
    def test_extracts_primary_compile_diagnostics_and_formats_failure_output(self):
        tool = CodeQLAnalyzeTool()
        query_file = "/tmp/UseAfterFree.ql"
        compile_output = (
            "ERROR: unexpected input ')' expecting one of: Lowerid "
            f"({query_file}:126,5-6)\n"
            "WARNING: module 'DataFlow' has been deprecated and may be removed in future "
            f"({query_file}:105,5-13)\n"
            "WARNING: module 'DataFlow' has been deprecated and may be removed in future "
            "(/tmp/library.qll:77,3-11)\n"
        )

        diagnostics = tool._extract_compile_diagnostics(compile_output, query_file)

        self.assertEqual(len(diagnostics), 3)
        self.assertTrue(diagnostics[0]["is_primary"])
        self.assertEqual(diagnostics[0]["severity"], "ERROR")
        self.assertEqual(diagnostics[0]["line"], 126)
        self.assertEqual(diagnostics[0]["column"], 5)

        suggestions = tool._build_repair_suggestions(compile_output)
        self.assertTrue(any("and" in item or "括号" in item for item in suggestions))

        formatted = tool._format_compile_failure_output(
            compile_output=compile_output,
            query_file=query_file,
            diagnostics=diagnostics,
            suggestions=suggestions,
        )
        self.assertIn("关键诊断:", formatted)
        self.assertIn("ERROR [当前查询 126:5]", formatted)
        self.assertIn("修复建议:", formatted)
        self.assertIn("原始输出:", formatted)


if __name__ == "__main__":
    unittest.main()
