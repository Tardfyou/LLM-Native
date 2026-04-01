import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.agent.tools import ToolRegistry
from src.generate.agent import LangChainGenerateAgent
from src.tools.knowledge import SearchKnowledgeTool


class _DummyLLM:
    pass


class KnowledgeGuidanceTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "paths": {
                "prompts_dir": str(PROJECT_ROOT / "prompts"),
            },
            "agent": {
                "max_iterations": 8,
                "generate_max_knowledge_search_calls": 2,
                "required_knowledge_min_similarity": 0.35,
                "required_knowledge_min_results": 1,
            },
        }

    def test_generate_normalizes_relookup_uaf_query_away_from_freedsymbol_terms(self):
        agent = LangChainGenerateAgent(
            config=self.config,
            tool_registry=ToolRegistry(),
            analyzer="csa",
            llm_override=_DummyLLM(),
        )
        analysis_metadata = {
            "vulnerability_patterns": [{"pattern_type": "use_after_free"}],
            "detection_strategy": {
                "suggestions": [
                    "prefer missing authoritative relookup over plain null-check reasoning",
                    "track session_id validity state alongside pointer invalidation",
                ]
            },
            "patch_semantics": {
                "added_api_calls": ["find_session"],
                "state_resets": ["ctx->session = NULL;", "ctx->session_id = -1;"],
                "lifecycle_changes": ["session = find_session(ctx->session_id);"],
            },
        }

        query = agent._normalize_knowledge_query(
            raw_query="Clang Static Analyzer use-after-free checker example with ProgramStateTrait for freed symbols",
            analyzer="csa",
            patch_text=(
                "destroy_session(ctx->session);\n"
                "ctx->session = NULL;\n"
                "ctx->session_id = -1;\n"
                "session = find_session(ctx->session_id);\n"
            ),
            analysis_metadata=analysis_metadata,
        )

        lowered = query.lower()
        self.assertIn("cached pointer", lowered)
        self.assertIn("stable handle", lowered)
        self.assertIn("authoritative relookup", lowered)
        self.assertIn("memberexpr", lowered)
        self.assertIn("find_session", lowered)
        self.assertNotIn("programstatetrait", lowered)
        self.assertNotIn("freed symbols", lowered)

    def test_search_rerank_prefers_relookup_seed_over_generic_freedsymbol_doc(self):
        tool = SearchKnowledgeTool(None, analyzer="csa")
        generic_freedsymbol = {
            "content": (
                "# Generic freed-symbol plugin\n"
                "ProgramStateTrait FreedSymbols checkPostCall checkLocation checkBind\n"
            ),
            "metadata": {"source": "checker_examples"},
            "distance": 0.35,
            "similarity": 0.65,
        }
        relookup_seed = {
            "content": (
                "# Consumer-side stale cache seed\n"
                "cached pointer stable handle authoritative relookup missing-relookup memberexpr\n"
            ),
            "metadata": {"source": "checker_examples"},
            "distance": 0.53,
            "similarity": 0.47,
        }
        reranked = tool._rerank_results(
            [generic_freedsymbol, relookup_seed],
            (
                "Clang Static Analyzer use-after-free checker example with ProgramStateTrait for freed symbols, "
                "tracking pointer invalidation, authoritative relookup, stable handle sibling field, "
                "cached pointer direct dereference, memberexpr"
            ),
            "csa",
            2,
        )

        self.assertEqual(reranked[0]["content"], relookup_seed["content"])

    def test_generate_exact_edits_reject_missing_or_ambiguous_targets(self):
        agent = LangChainGenerateAgent(
            config=self.config,
            tool_registry=ToolRegistry(),
            analyzer="codeql",
            llm_override=_DummyLLM(),
        )

        missing = agent._build_patch_from_exact_edits(
            file_name="test.ql",
            original_text="line one\nline two\nline three\n",
            edits=[{"old_snippet": "line missing\n", "new_snippet": "line updated\n"}],
        )
        self.assertIn("未在当前产物中命中", missing["error"])

        ambiguous = agent._build_patch_from_exact_edits(
            file_name="test.ql",
            original_text="same\nsame\n",
            edits=[{"old_snippet": "same\n", "new_snippet": "updated\n"}],
        )
        self.assertIn("不唯一", ambiguous["error"])


if __name__ == "__main__":
    unittest.main()
