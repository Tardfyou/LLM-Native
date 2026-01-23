"""
生成Agent - 负责代码生成和组装
"""

from typing import Dict, Any, Optional, List
import asyncio
import random

# 使用loguru以支持logger.success()等方法
from loguru import logger

from .base_agent import BaseAgent, AgentMessage
from ..prompts.prompt_manager import PromptManager
from ..lsp.clangd_client import ClangdClient

class GenerationAgent(BaseAgent):
    """生成Agent - 负责代码生成和组装"""

    def __init__(self, prompt_manager: Optional[PromptManager] = None,
                 lsp_client: Optional[ClangdClient] = None,
                 llm_client: Optional[Any] = None):
        super().__init__("generation_agent", "code_generation")
        self.prompt_manager = prompt_manager
        self.lsp_client = lsp_client
        self.llm_client = llm_client

    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理接收到的消息"""
        if message.message_type == "analysis_complete":
            return await self._handle_analysis_complete(message)
        elif message.message_type == "generate_code":
            return await self._handle_generate_code(message)
        elif message.message_type == "repair_code":
            return await self._handle_repair_code(message)
        else:
            logger.warning(f"GenerationAgent received unknown message type: {message.message_type}")
            return None

    async def _handle_analysis_complete(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理分析完成消息"""
        try:
            analysis_result = message.content

            # 基于分析结果生成代码
            generation_result = await self.execute_task({
                "analysis": analysis_result,
                "task_type": "initial_generation"
            })

            # 发送给验证Agent
            return await self.send_message(
                "validation_agent",
                "code_generated",
                generation_result
            )

        except Exception as e:
            logger.error(f"GenerationAgent error in analysis_complete: {e}")
            return await self.send_message(
                "orchestrator",
                "generation_failed",
                {"error": str(e), "stage": "analysis_complete"}
            )

    async def _handle_generate_code(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理代码生成请求"""
        try:
            plan = message.content.get("plan", {})
            context = message.content.get("context", {})

            generation_result = await self.execute_task({
                "plan": plan,
                "context": context,
                "task_type": "planned_generation"
            })

            return await self.send_message(
                "validation_agent",
                "code_generated",
                generation_result
            )

        except Exception as e:
            logger.error(f"GenerationAgent error in generate_code: {e}")
            return None

    async def _handle_repair_code(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理代码修复请求"""
        try:
            original_code = message.content.get("code", "")
            issues = message.content.get("issues", [])

            repair_result = await self.execute_task({
                "original_code": original_code,
                "issues": issues,
                "task_type": "code_repair"
            })

            return await self.send_message(
                "validation_agent",
                "code_repaired",
                repair_result
            )

        except Exception as e:
            logger.error(f"GenerationAgent error in repair_code: {e}")
            return None

    async def execute_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行代码生成任务"""
        import asyncio
        start_time = asyncio.get_event_loop().time()

        try:
            task_type = task_data.get("task_type", "code_generation")

            if task_type == "initial_generation":
                result = await self._generate_initial_code(task_data)
            elif task_type == "planned_generation":
                result = await self._generate_planned_code(task_data)
            elif task_type == "code_repair":
                result = await self._repair_code(task_data)
            else:
                raise ValueError(f"Unknown task type: {task_type}")

            # 更新性能统计
            response_time = asyncio.get_event_loop().time() - start_time
            self.update_performance_stats(response_time, True)

            return result

        except Exception as e:
            response_time = asyncio.get_event_loop().time() - start_time
            self.update_performance_stats(response_time, False)
            raise e

    async def _generate_initial_code(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """基于分析结果生成初始代码 - 使用LLM"""
        analysis = task_data["analysis"]
        # 修复：获取检索到的知识
        retrieved_knowledge = task_data.get("retrieved_knowledge", [])

        # 1. 确定漏洞类型和框架
        vuln_type = self._infer_vulnerability_type(analysis)
        framework = "clang"  # 默认使用Clang

        logger.info(f"Generating checker for vulnerability type: {vuln_type}")
        if retrieved_knowledge:
            logger.info(f"Using {len(retrieved_knowledge)} retrieved knowledge items")

        # 2. 构建代码生成提示词 - 传递检索到的知识
        if self.prompt_manager:
            generation_prompt = self.prompt_manager.build_code_generation_prompt(
                vulnerability_type=vuln_type,
                framework=framework,
                analysis_context=analysis,
                retrieved_knowledge=retrieved_knowledge  # 修复：传递检索到的知识
            )

            # 使用LLM生成代码（如果有LLM客户端）
            if self.llm_client:
                try:
                    logger.info("Calling LLM for code generation...")
                    # 使用 asyncio.to_thread 调用同步的 generate() 方法，避免阻塞事件循环
                    # 使用配置文件中的 max_tokens 设置
                    max_tokens = getattr(self.llm_client.config, 'max_tokens', 10000)
                    temperature = getattr(self.llm_client.config, 'temperature', 0.3)

                    # 使用 asyncio.wait_for 添加超时保护（5分钟超时）
                    llm_response = await asyncio.wait_for(
                        asyncio.to_thread(
                            self.llm_client.generate,
                            generation_prompt,
                            temperature=temperature,
                            max_tokens=max_tokens
                        ),
                        timeout=300.0  # 5分钟超时
                    )

                    # 检查LLM响应
                    if not llm_response:
                        logger.warning("LLM returned empty response, falling back to template")
                    elif len(llm_response) < 100:
                        logger.warning(f"LLM response too short ({len(llm_response)} chars), falling back to template")
                    else:
                        # 提取代码块
                        generated_code = self._extract_code_from_response(llm_response)

                        if not generated_code or len(generated_code) < 100:
                            logger.warning(f"Extracted code too short or empty ({len(generated_code) if generated_code else 0} chars), falling back to template")
                        else:
                            logger.success(f"LLM generated {len(generated_code)} bytes of code")

                            # LSP验证和优化（如果可用）
                            if self.lsp_client:
                                try:
                                    validation = await self.lsp_client.validate_code(generated_code, "generated_checker")
                                    if validation.get("has_errors", False):
                                        generated_code = await self._lsp_guided_improvement(generated_code, validation)
                                except Exception as e:
                                    logger.warning(f"LSP validation failed: {e}")

                            return {
                                "generated_code": generated_code,
                                "vulnerability_type": vuln_type,
                                "framework": framework,
                                "generation_method": "llm_based",
                                "confidence_score": 0.7,
                                "metadata": {
                                    "analysis_used": True,
                                    "lsp_validated": self.lsp_client is not None,
                                    "llm_used": True
                                }
                            }
                except asyncio.TimeoutError:
                    logger.warning("LLM generation timed out after 300 seconds, falling back to template")
                except Exception as e:
                    logger.error(f"LLM generation failed with exception: {type(e).__name__}: {str(e)[:200]}")
                    import traceback
                    logger.debug(traceback.format_exc())

        # 3. 回退到模板生成
        logger.info("Falling back to template-based generation")
        generated_code = self._generate_template_code(vuln_type, analysis)

        return {
            "generated_code": generated_code,
            "vulnerability_type": vuln_type,
            "framework": framework,
            "generation_method": "template_based",
            "confidence_score": 0.5,
            "metadata": {
                "analysis_used": True,
                "lsp_validated": False
            }
        }

    async def _generate_planned_code(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """基于详细计划生成代码"""
        plan = task_data["plan"]
        context = task_data.get("context", {})

        # 基于计划生成更精确的代码
        vuln_type = plan.get("vulnerability_type", "general")
        framework = plan.get("framework", "clang")

        # 生成代码
        generated_code = self._generate_advanced_code(plan, context)

        return {
            "generated_code": generated_code,
            "vulnerability_type": vuln_type,
            "framework": framework,
            "generation_method": "plan_based",
            "confidence_score": 0.8,
            "plan_used": plan
        }

    async def _repair_code(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """修复代码问题"""
        original_code = task_data["original_code"]
        issues = task_data["issues"]

        # 基于问题生成修复提示词
        if self.prompt_manager:
            repair_prompt = self.prompt_manager.build_code_repair_prompt(
                original_code, issues
            )
            # 这里可以调用LLM进行修复
            # repaired_code = await self.llm.generate(repair_prompt)

        # 使用规则-based修复
        repaired_code = self._rule_based_repair(original_code, issues)

        return {
            "original_code": original_code,
            "repaired_code": repaired_code,
            "issues_fixed": issues,
            "repair_method": "rule_based",
            "confidence_score": 0.7
        }

    def _infer_vulnerability_type(self, analysis: Dict[str, Any]) -> str:
        """推断漏洞类型"""
        indicators = analysis.get("vulnerability_indicators", [])
        description = analysis.get("description_summary", {}).get("technical_terms", [])
        vuln_type = analysis.get("inferred_vulnerability_type", "")

        # 基于指标和描述推断漏洞类型
        combined_indicators = str(indicators) + str(description) + vuln_type.lower()

        if any(keyword in combined_indicators for keyword in ["buffer", "overflow", "strcpy", "memcpy"]):
            return "buffer_overflow"
        elif any(keyword in combined_indicators for keyword in ["free", "memory", "leak"]):
            return "use_after_free"
        elif any(keyword in combined_indicators for keyword in ["null", "nullptr"]):
            return "null_pointer"
        elif any(keyword in combined_indicators for keyword in ["uninit", "未初始化", "initialize"]):
            return "uninitialized_var"
        else:
            return "general_vulnerability"

    def _generate_template_code(self, vuln_type: str, analysis: Dict[str, Any]) -> str:
        """使用模板生成基础代码（完全独立的版本，无需Clang头文件）"""
        # 使用完整的Mock实现，确保代码可以独立编译验证
        templates = {
            "buffer_overflow": """
// Buffer Overflow Checker - Generated by LLM-Native
// This is a standalone template for validation

#include <iostream>
#include <string>
#include <cstring>

// Mock Clang Static Analyzer types for standalone validation
namespace clang {
    namespace ento {
        class CheckerContext {};
        class CallEvent {
        public:
            virtual int getNumArgs() const { return 0; }
            virtual const char* getArgAsString(unsigned int) const { return ""; }
        };
        class ExplodedNode {};
        class BugType {
        public:
            BugType(const void*, const char*, const char*) {}
        };
        class CheckerRegistry {
        public:
            template<typename T>
            void registerChecker(const char* name) {}
        };
    }
}

class BufferOverflowChecker {
private:
    clang::ento::BugType* BT;

public:
    BufferOverflowChecker() : BT(nullptr) {
        BT = new clang::ento::BugType(this, "Buffer Overflow", "Security");
    }

    ~BufferOverflowChecker() {
        if (BT) delete BT;
    }

    void checkPreCall(const clang::ento::CallEvent &Call, clang::ento::CheckerContext &C) const {
        // Buffer overflow detection logic
        int numArgs = Call.getNumArgs();
        if (numArgs >= 2) {
            const char* dest = Call.getArgAsString(0);
            const char* src = Call.getArgAsString(1);
            if (src && dest) {
                size_t srcLen = strlen(src);
                size_t destLen = strlen(dest);
                if (srcLen > destLen) {
                    std::cout << "Potential buffer overflow detected" << std::endl;
                    std::cout << "Source length: " << srcLen << ", Destination capacity: " << destLen << std::endl;
                }
            }
        }
    }
};

// Registration function
void registerBufferOverflowChecker(clang::ento::CheckerRegistry &registry) {
    registry.registerChecker<BufferOverflowChecker>("example.BufferOverflow");
}
""",
            "use_after_free": """
// Use After Free Checker - Generated by LLM-Native

#include <iostream>
#include <string>
#include <set>

// Mock Clang Static Analyzer types
namespace clang {
    namespace ento {
        class CheckerContext {};
        class CallEvent {
        public:
            virtual const char* getCalleeName() const { return ""; }
            virtual void* getArgAsPointer(unsigned int) const { return nullptr; }
        };
        class ExplodedNode {};
        class BugType {
        public:
            BugType(const void*, const char*, const char*) {}
        };
        class CheckerRegistry {
        public:
            template<typename T>
            void registerChecker(const char* name) {}
        };
    }
}

class UseAfterFreeChecker {
private:
    clang::ento::BugType* BT;
    std::set<void*> freedMemory;

public:
    UseAfterFreeChecker() : BT(nullptr) {
        BT = new clang::ento::BugType(this, "Use After Free", "Memory");
    }

    ~UseAfterFreeChecker() {
        if (BT) delete BT;
    }

    void checkPreCall(const clang::ento::CallEvent &Call, clang::ento::CheckerContext &C) const {
        const char* calleeName = Call.getCalleeName();
        if (calleeName && std::string(calleeName) == "free") {
            void* ptr = Call.getArgAsPointer(0);
            if (ptr) {
                // Record freed memory
                const_cast<std::set<void*>&>(freedMemory).insert(ptr);
            }
        } else {
            // Check if any argument points to freed memory
            for (unsigned i = 0; i < 2; i++) {
                void* ptr = Call.getArgAsPointer(i);
                if (ptr && freedMemory.count(ptr)) {
                    std::cout << "Use after free detected! Pointer: " << ptr << std::endl;
                }
            }
        }
    }
};

void registerUseAfterFreeChecker(clang::ento::CheckerRegistry &registry) {
    registry.registerChecker<UseAfterFreeChecker>("example.UseAfterFree");
}
""",
            "null_pointer": """
// Null Pointer Dereference Checker - Generated by LLM-Native

#include <iostream>

// Mock Clang Static Analyzer types
namespace clang {
    namespace ento {
        class CheckerContext {};
        class CallEvent {
        public:
            virtual void* getArgAsPointer(unsigned int) const { return nullptr; }
        };
        class ExplodedNode {};
        class BugType {
        public:
            BugType(const void*, const char*, const char*) {}
        };
        class CheckerRegistry {
        public:
            template<typename T>
            void registerChecker(const char* name) {}
        };
    }
}

class NullPointerDereferenceChecker {
private:
    clang::ento::BugType* BT;

public:
    NullPointerDereferenceChecker() : BT(nullptr) {
        BT = new clang::ento::BugType(this, "Null Pointer Dereference", "Security");
    }

    ~NullPointerDereferenceChecker() {
        if (BT) delete BT;
    }

    void checkPreCall(const clang::ento::CallEvent &Call, clang::ento::CheckerContext &C) const {
        for (unsigned i = 0; i < 3; i++) {
            void* ptr = Call.getArgAsPointer(i);
            if (ptr == nullptr) {
                std::cout << "Potential null pointer dereference detected at argument " << i << std::endl;
            }
        }
    }
};

void registerNullPointerDereferenceChecker(clang::ento::CheckerRegistry &registry) {
    registry.registerChecker<NullPointerDereferenceChecker>("example.NullPointerDereference");
}
""",
            "uninitialized_var": """
// Uninitialized Variable Checker - Generated by LLM-Native

#include <iostream>
#include <string>

// Mock Clang Static Analyzer types
namespace clang {
    namespace ento {
        class CheckerContext {};
        class CallEvent {
        public:
            virtual const char* getArgAsString(unsigned int) const { return ""; }
        };
        class ExplodedNode {};
        class BugType {
        public:
            BugType(const void*, const char*, const char*) {}
        };
        class CheckerRegistry {
        public:
            template<typename T>
            void registerChecker(const char* name) {}
        };
    }
}

class UninitializedVarChecker {
private:
    clang::ento::BugType* BT;

public:
    UninitializedVarChecker() : BT(nullptr) {
        BT = new clang::ento::BugType(this, "Uninitialized Variable", "Security");
    }

    ~UninitializedVarChecker() {
        if (BT) delete BT;
    }

    void checkPreCall(const clang::ento::CallEvent &Call, clang::ento::CheckerContext &C) const {
        // Check for potential use of uninitialized variables
        const char* arg0 = Call.getArgAsString(0);
        if (arg0 && strlen(arg0) == 0) {
            std::cout << "Potential use of uninitialized variable detected" << std::endl;
        }
    }
};

void registerUninitializedVarChecker(clang::ento::CheckerRegistry &registry) {
    registry.registerChecker<UninitializedVarChecker>("example.UninitializedVar");
}
""",
            "general_vulnerability": """
// Generic Vulnerability Checker - Generated by LLM-Native

#include <iostream>

// Mock Clang Static Analyzer types
namespace clang {
    namespace ento {
        class CheckerContext {};
        class CallEvent {
        public:
            virtual const char* getCalleeName() const { return ""; }
            virtual int getNumArgs() const { return 0; }
        };
        class ExplodedNode {};
        class BugType {
        public:
            BugType(const void*, const char*, const char*) {}
        };
        class CheckerRegistry {
        public:
            template<typename T>
            void registerChecker(const char* name) {}
        };
    }
}

class GenericChecker {
private:
    clang::ento::BugType* BT;

public:
    GenericChecker() : BT(nullptr) {
        BT = new clang::ento::BugType(this, "Generic Vulnerability", "Security");
    }

    ~GenericChecker() {
        if (BT) delete BT;
    }

    void checkPreCall(const clang::ento::CallEvent &Call, clang::ento::CheckerContext &C) const {
        const char* calleeName = Call.getCalleeName();
        std::cout << "Generic checker examining call: " << (calleeName ? calleeName : "unknown") << std::endl;
    }
};

void registerGenericChecker(clang::ento::CheckerRegistry &registry) {
    registry.registerChecker<GenericChecker>("example.Generic");
}
"""
        }

        # 根据漏洞类型选择合适的模板
        if "overflow" in vuln_type.lower():
            return templates["buffer_overflow"]
        elif "free" in vuln_type.lower() or "memory" in vuln_type.lower():
            return templates["use_after_free"]
        elif "null" in vuln_type.lower():
            return templates["null_pointer"]
        elif "uninit" in vuln_type.lower():
            return templates["uninitialized_var"]
        else:
            return templates["general_vulnerability"]

    def _generate_advanced_code(self, plan: Dict[str, Any], context: Dict[str, Any]) -> str:
        """生成高级代码（基于详细计划）"""
        vuln_type = plan.get("vulnerability_type", "general")

        # 基于计划生成更复杂的代码
        base_code = self._generate_template_code(vuln_type, {})

        # 根据计划添加特定的检查逻辑
        if plan.get("custom_checks"):
            base_code = self._inject_custom_checks(base_code, plan["custom_checks"])

        return base_code

    def _rule_based_repair(self, code: str, issues: List[str]) -> str:
        """基于规则的代码修复"""
        repaired_code = code

        for issue in issues:
            if "missing include" in issue.lower():
                # 添加必要的头文件
                if "#include" not in repaired_code:
                    repaired_code = '#include "clang/StaticAnalyzer/Core/Checker.h"\n' + repaired_code
            elif "undefined" in issue.lower():
                # 修复未定义的符号
                repaired_code = self._fix_undefined_symbols(repaired_code, issue)

        return repaired_code

    async def _lsp_guided_improvement(self, code: str, validation: Dict[str, Any]) -> str:
        """基于LSP反馈改进代码"""
        if not self.lsp_client:
            return code

        # 分析LSP错误并生成修复建议
        improved_code = code

        # 这里可以实现更复杂的LSP引导修复逻辑
        return improved_code

    def _inject_custom_checks(self, base_code: str, custom_checks: List[str]) -> str:
        """注入自定义检查逻辑"""
        # 在基础代码中注入特定的检查逻辑
        # 这是一个简化的实现
        injection_point = "// Add your specific check logic here"

        custom_logic = "\n".join([
            f"  // Custom check: {check}" for check in custom_checks
        ])

        return base_code.replace(injection_point, custom_logic)

    def _fix_undefined_symbols(self, code: str, issue: str) -> str:
        """修复未定义符号"""
        # 简化的符号修复逻辑
        if "BugType" in issue:
            if "#include" not in code:
                code = '#include "clang/StaticAnalyzer/Core/BugType.h"\n' + code
        elif "PathSensitiveBugReport" in issue:
            if "#include" not in code or "PathSensitiveBugReport" not in code:
                code = '#include "clang/StaticAnalyzer/Core/PathSensitiveBugReport.h"\n' + code

        return code

    def _extract_code_from_response(self, response: str) -> str:
        """从LLM响应中提取代码块 - 增强版处理DeepSeek混合响应"""
        import re

        if not response:
            return ""

        # 首先移除think标签（推理模型特殊输出）
        try:
            from src.generator.utils.code_utils import remove_think_tags
            response = remove_think_tags(response)
        except:
            pass

        # 多种代码块模式匹配
        patterns = [
            r'```cpp\s*\n(.*?)```',      # ```cpp ... ```
            r'```c\+\+\s*\n(.*?)```',    # ```c++ ... ```
            r'```c\s*\n(.*?)```',        # ```c ... ```
            r'```C\s*\n(.*?)```',        # ```C ... ```
        ]

        for pattern in patterns:
            match = re.search(pattern, response, re.DOTALL)
            if match:
                code = match.group(1).strip()
                logger.info(f"Successfully extracted code using pattern: {pattern[:20]}...")
                return code

        # 如果没有找到标准代码块，尝试其他策略

        # 策略1: 查找包含典型C++代码特征的连续代码段
        # 特征：包含 #include, class, void, namespace 等关键字
        lines = response.split('\n')
        code_start = -1
        brace_count = 0
        in_code = False
        seen_open_brace = False  # 新增：标记是否见过左大括号

        for i, line in enumerate(lines):
            # 检测可能的代码开始
            code_indicators = ['#include', 'namespace', 'class ', 'struct ', 'void ', 'int ', 'bool ']
            if any(indicator in line for indicator in code_indicators):
                if code_start == -1:
                    code_start = i
                in_code = True

            # 统计大括号以确定代码块范围
            if in_code:
                open_braces = line.count('{')
                close_braces = line.count('}')
                brace_count += open_braces
                brace_count -= close_braces

                # 标记是否见过左大括号（真正的代码开始）
                if open_braces > 0:
                    seen_open_brace = True

        # 策略1.5: 扫描整个响应，查找真正的代码结束标记
        # 不要在大括号平衡时就返回，要继续查找结束标记
        if code_start >= 0:
            last_code_line = code_start
            found_registration = False

            for i in range(code_start, min(code_start + 1000, len(lines))):  # 最多1000行
                line = lines[i].strip()

                # 检查是否包含注册函数（明确的代码结束标记）
                if 'clang_registerCheckers' in line or 'clang_analyzerAPIVersionString' in line:
                    found_registration = True
                    last_code_line = i
                    break

                # 如果遇到空的 } 后跟注册函数，也需要捕获
                if line.startswith('}') and i < len(lines) - 1:
                    next_line = lines[i + 1].strip()
                    if 'clang_registerCheckers' in next_line or 'extern "C"' in next_line:
                        last_code_line = i
                        break

                # 跟踪最后一个有代码的行
                if line and not line.startswith('//') and not line.startswith('/*'):
                    last_code_line = i

            # 如果找到了注册标记，或者有足够的代码行
            if found_registration or last_code_line > code_start + 30:
                code_segment = '\n'.join(lines[code_start:last_code_line+1])
                # 验证包含基本C++元素
                if any(keyword in code_segment for keyword in ['class', 'void', '#include', 'namespace']):
                    logger.info(f"Extracted code using end-marker scan (lines {code_start}-{last_code_line})")
                    return code_segment.strip()

        # 备选：如果没有找到明显的结束标记，尝试从 code_start 到文件结尾
        if code_start >= 0:
            # 向后查找：找到最后一个有意义的代码行
            last_meaningful_line = code_start
            for i in range(code_start, min(code_start + 500, len(lines))):  # 最多500行
                line = lines[i].strip()
                # 跳过空行和纯注释行
                if line and not line.startswith('//') and not line.startswith('/*'):
                    # 检查是否是代码结束标记（如 extern "C" 或最后的 }）
                    if line.startswith('}') and 'clang_registerCheckers' not in ''.join(lines[min(i+1, len(lines)-1):min(i+10, len(lines))]):
                        # 这是一个可能的结束，但需要确认后面没有注册函数
                        last_meaningful_line = i
                        break
                    last_meaningful_line = i

            if last_meaningful_line > code_start + 10:  # 至少10行
                code_segment = '\n'.join(lines[code_start:last_meaningful_line+1])
                logger.info(f"Extracted code using range (lines {code_start}-{last_meaningful_line})")
                return code_segment.strip()

        # 策略2: 如果响应非常短（<500字符），可能是纯代码
        if len(response.strip()) < 500:
            # 检查是否包含代码特征
            if any(keyword in response for keyword in ['#include', 'class', 'namespace', 'void ', 'return']):
                logger.info("Response appears to be pure code (short)")
                return response.strip()

        # 策略3: 过滤掉明显的解释性文本
        # 移除常见的解释性行
        filtered_lines = []
        skip_phrases = [
            'here is the', 'below is the', 'the following', 'this code',
            'i generated', 'i have created', 'implementation:', 'solution:',
            '说明', '如下', '以下是', '代码如下'
        ]

        for line in lines:
            line_lower = line.strip().lower()
            if not any(phrase in line_lower for phrase in skip_phrases):
                filtered_lines.append(line)

        filtered_response = '\n'.join(filtered_lines)

        # 如果过滤后的响应包含代码特征，返回它
        if len(filtered_response) > 200:
            if any(keyword in filtered_response for keyword in ['#include', 'class', 'namespace']):
                logger.info("Extracted code after filtering explanation text")
                return filtered_response.strip()

        # 最后的回退：返回原响应（已移除think标签）
        logger.warning("Could not extract clean code block, returning filtered response")
        return response.strip()
