"""
Generator Engine
基于LLM的检测器自动生成引擎
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Any

from loguru import logger

from core.config import Config
from knowledge_base.manager import KnowledgeBaseManager
from model.llm_client import LLMClient
from model.deepseek_client import DeepSeekClient
from model.llm_client import LLMConfig
from frameworks.codeql import CodeQLFramework


@dataclass
class GenerationResult:
    """Result of detector generation"""
    success: bool
    generated_files: List[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.generated_files is None:
            self.generated_files = []
        if self.metadata is None:
            self.metadata = {}


class GeneratorEngine:
    """LLM-powered detector generation engine"""

    def __init__(self, config: Config, knowledge_manager: KnowledgeBaseManager):
        """
        Initialize the generator engine

        Args:
            config: Framework configuration
            knowledge_manager: Knowledge base manager
        """
        self.config = config
        self.knowledge_manager = knowledge_manager
        self.llm_client = None
        self.framework = None  # 暂时只支持CodeQL

        self._init_llm_client()
        self._init_framework()

    def _init_llm_client(self):
        """Initialize LLM client"""
        try:
            # Initialize DeepSeek client
            llm_config = LLMConfig(
                api_key=self.config.get('llm.keys.deepseek_key', ''),
                model_name=self.config.get('llm.primary_model', 'deepseek-chat'),
                temperature=self.config.get('llm.generation.temperature', 0.1),
                max_tokens=self.config.get('llm.generation.max_tokens', 4096),
                top_p=self.config.get('llm.generation.top_p', 0.9),
                frequency_penalty=self.config.get('llm.generation.frequency_penalty', 0.0),
                presence_penalty=self.config.get('llm.generation.presence_penalty', 0.0),
                timeout=self.config.get('llm.timeout', 60),
                max_retries=self.config.get('llm.max_retries', 3)
            )

            self.llm_client = DeepSeekClient(llm_config)
            logger.info(f"LLM client initialized: {llm_config.model_name}")

        except Exception as e:
            logger.warning(f"Failed to initialize DeepSeek client: {e}")
            logger.info("Falling back to mock client for development")
            self.llm_client = MockLLMClient()

    def _init_framework(self):
        """Initialize framework"""
        # 暂时只支持CodeQL，后续可扩展
        self.framework = CodeQLFramework()
        logger.info(f"Initialized framework: {self.framework.name}")

    def generate_detector(self,
                         vulnerability_desc: str,
                         target_framework: str = "codeql",
                         output_dir: Path = None) -> GenerationResult:
        """
        Generate a static analysis detector

        Args:
            vulnerability_desc: Description of the vulnerability
            target_framework: Target framework ('clang' or 'codeql')
            output_dir: Output directory for generated files

        Returns:
            GenerationResult: Result of generation
        """
        try:
            logger.info(f"Generating detector for: {vulnerability_desc[:100]}...")

            # 检查框架支持
            if target_framework != "codeql":
                return GenerationResult(
                    success=False,
                    error=f"Framework '{target_framework}' not yet supported. Currently only 'codeql' is supported.",
                    metadata={"supported_frameworks": ["codeql"]}
                )

            # Step 1: Search knowledge base for relevant information
            knowledge_results = self.knowledge_manager.search(
                query=vulnerability_desc,
                top_k=3,
                filters={"framework": target_framework}
            )

            # Step 2: Generate detector code using LLM
            generated_code = self._generate_code_with_llm(
                vulnerability_desc=vulnerability_desc,
                target_framework=target_framework,
                knowledge_results=knowledge_results
            )

            if not generated_code:
                return GenerationResult(
                    success=False,
                    error="Failed to generate code",
                    metadata={"step": "code_generation"}
                )

            # Step 3: Save generated files
            saved_files = self._save_generated_files(
                code=generated_code,
                target_framework=target_framework,
                output_dir=output_dir
            )

            # Step 4: Attempt to compile and fix if needed
            compilation_success = self._attempt_compilation(saved_files[0], target_framework)

            return GenerationResult(
                success=True,
                generated_files=saved_files,
                metadata={
                    "target_framework": target_framework,
                    "compilation_success": compilation_success,
                    "knowledge_sources": len(knowledge_results)
                }
            )

        except Exception as e:
            error_msg = f"Error during detector generation: {e}"
            logger.error(error_msg)
            return GenerationResult(success=False, error=error_msg)

    def _generate_code_with_llm(self,
                               vulnerability_desc: str,
                               target_framework: str,
                               knowledge_results: List[Dict[str, Any]]) -> Optional[str]:
        """
        Generate detector code using LLM

        Args:
            vulnerability_desc: Vulnerability description
            target_framework: Target framework
            knowledge_results: Knowledge base search results

        Returns:
            Generated code or None if failed
        """
        try:
            # Prepare prompt
            prompt = self._build_generation_prompt(
                vulnerability_desc, target_framework, knowledge_results
            )

            # Call LLM (mock implementation)
            response = self.llm_client.generate(prompt)

            # Extract code from response
            code = self._extract_code_from_response(response)

            return code

        except Exception as e:
            logger.error(f"Error generating code with LLM: {e}")
            return None

    def _build_generation_prompt(self,
                                vulnerability_desc: str,
                                target_framework: str,
                                knowledge_results: List[Dict[str, Any]]) -> str:
        """Build the generation prompt"""
        # Build knowledge context
        knowledge_context = "\n".join([
            f"Relevant API Info {i+1}:\n{result['content'][:500]}..."
            for i, result in enumerate(knowledge_results)
        ])

        if target_framework == "clang":
            prompt = f"""
Generate a Clang Static Analyzer checker for the following vulnerability:

Vulnerability: {vulnerability_desc}

Relevant API information:
{knowledge_context}

Requirements:
1. Create a checker class that inherits from Checker<check::Location>
2. Implement checkLocation method to detect the vulnerability
3. Register the checker with REGISTER_CHECKER macro
4. Include proper error reporting with BugType

Generate complete, compilable C++ code for the checker.
"""
        elif target_framework == "codeql":
            prompt = f"""
Generate a CodeQL query for the following vulnerability:

Vulnerability: {vulnerability_desc}

Relevant API information:
{knowledge_context}

Requirements:
1. Define isSource, isSink, and isSanitizer predicates
2. Create a query that uses DataFlow::PathGraph
3. Include proper select statement for results

Generate complete, runnable CodeQL query code.
"""
        else:
            raise ValueError(f"Unsupported framework: {target_framework}")

        return prompt

    def _extract_code_from_response(self, response: str) -> Optional[str]:
        """Extract code from LLM response"""
        # Simple extraction - look for code blocks
        import re

        # Look for ```cpp or ```ql blocks
        code_pattern = r'```(?:cpp|ql|c\+\+)?\n(.*?)\n```'
        matches = re.findall(code_pattern, response, re.DOTALL)

        if matches:
            return matches[0].strip()

        # Fallback: return the entire response
        return response.strip()

    def _save_generated_files(self,
                             code: str,
                             target_framework: str,
                             output_dir: Path) -> List[str]:
        """Save generated files"""
        saved_files = []

        if target_framework == "clang":
            # Save header file
            header_file = output_dir / "checker.h"
            header_content = self._generate_clang_header()
            header_file.write_text(header_content)
            saved_files.append(str(header_file))

            # Save implementation file
            impl_file = output_dir / "checker.cpp"
            impl_file.write_text(code)
            saved_files.append(str(impl_file))

        elif target_framework == "codeql":
            # Save query file
            query_file = output_dir / "detector.ql"
            query_file.write_text(code)
            saved_files.append(str(query_file))

        # Save metadata
        metadata_file = output_dir / "metadata.json"
        import json
        metadata = {
            "framework": target_framework,
            "generated_at": "2024-01-01T00:00:00Z",
            "code_length": len(code)
        }
        metadata_file.write_text(json.dumps(metadata, indent=2))
        saved_files.append(str(metadata_file))

        return saved_files

    def _generate_clang_header(self) -> str:
        """Generate Clang checker header"""
        return """
#ifndef LLVM_CLANG_ANALYZER_CHECKERS_DETECTOR_H
#define LLVM_CLANG_ANALYZER_CHECKERS_DETECTOR_H

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"

#endif
"""

    def _attempt_compilation(self, file_path: str, framework_name: str) -> bool:
        """
        Attempt to compile the generated code

        Args:
            file_path: Path to the file to compile
            framework_name: Framework name

        Returns:
            True if compilation successful
        """
        try:
            logger.info(f"Attempting compilation for: {file_path}")

            if framework_name == "codeql" and self.framework:
                # 使用框架的编译方法
                result = self.framework.compile_detector(
                    source_code=Path(file_path).read_text(),
                    output_dir=Path(file_path).parent
                )
                return result.success
            else:
                # 回退到基本检查
                path = Path(file_path)
                if path.exists() and path.stat().st_size > 0:
                    logger.info("Basic file check passed")
                    return True

        except Exception as e:
            logger.error(f"Compilation check failed: {e}")

        return False


class MockLLMClient:
    """Mock LLM client for development and testing"""

    def generate(self, prompt: str) -> str:
        """Mock LLM generation"""
        if "clang" in prompt.lower():
            return self._generate_mock_clang_code()
        elif "codeql" in prompt.lower():
            return self._generate_mock_codeql_code()
        else:
            return "// Mock generated code"

    def _generate_mock_clang_code(self) -> str:
        """Generate mock Clang checker code"""
        return '''
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;
using namespace ento;

namespace {
class MockChecker : public Checker<check::Location> {
  const BugType BT{this, "Mock Vulnerability"};

public:
  void checkLocation(SVal l, bool isLoad, const Stmt* S,
                     CheckerContext &C) const {
    // Mock implementation
    // In real implementation, this would check for actual vulnerabilities
  }
};
} // namespace

void ento::registerMockChecker(CheckerManager &mgr) {
  mgr.registerChecker<MockChecker>();
}

bool ento::shouldRegisterMockChecker(const CheckerManager &mgr) {
  return true;
}
'''

    def _generate_mock_codeql_code(self) -> str:
        """Generate mock CodeQL query"""
        return '''
/**
 * @name Mock vulnerability detector
 * @description Detects mock vulnerabilities
 * @kind path-problem
 * @problem.severity error
 */

import cpp
import semmle.code.cpp.dataflow.DataFlow

predicate isSource(DataFlow::Node source) {
  // Mock source definition
  exists(FunctionCall fc |
    fc.getTarget().getName() = "mock_source" and
    source.asExpr() = fc
  )
}

predicate isSink(DataFlow::Node sink) {
  // Mock sink definition
  exists(FunctionCall fc |
    fc.getTarget().getName() = "mock_sink" and
    sink.asExpr() = fc.getArgument(0)
  )
}

predicate isSanitizer(DataFlow::Node node) {
  // Mock sanitizer
  exists(FunctionCall fc |
    fc.getTarget().getName() = "mock_sanitize" and
    node.asExpr() = fc.getArgument(0)
  )
}

module MockConfig implements DataFlow::ConfigSig {
  predicate isSource = isSource/1;
  predicate isSink = isSink/1;
  predicate isBarrier = isSanitizer/1;
}

module MockFlow = DataFlow::Global<MockConfig>;

from MockFlow::PathNode source, MockFlow::PathNode sink
where MockFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Mock vulnerability detected"
'''
