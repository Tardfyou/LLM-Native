"""
基础Agent类
"""

import asyncio
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

# 使用loguru以支持logger.success()等方法
from loguru import logger

@dataclass
class AgentMessage:
    """Agent间通信消息"""

    sender: str
    receiver: str
    message_type: str  # analysis_result, generation_request, validation_complete
    content: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    message_id: str = field(default_factory=lambda: f"msg_{datetime.now().timestamp()}")

class BaseAgent(ABC):
    """Agent基类"""

    def __init__(self, name: str, expertise: str):
        self.name = name
        self.expertise = expertise
        self.message_queue = asyncio.Queue()
        self.is_active = False
        self.state = "idle"  # idle, working, waiting

        # 性能统计
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.average_response_time = 0.0

        logger.info(f"Agent {self.name} initialized with expertise: {self.expertise}")

    async def start(self):
        """启动Agent"""
        self.is_active = True
        self.state = "idle"
        logger.info(f"Agent {self.name} started")

    async def stop(self):
        """停止Agent"""
        self.is_active = False
        self.state = "stopped"
        logger.info(f"Agent {self.name} stopped")

    async def send_message(self, target_agent: str, message_type: str, content: Dict[str, Any]) -> AgentMessage:
        """发送消息给其他Agent"""
        message = AgentMessage(
            sender=self.name,
            receiver=target_agent,
            message_type=message_type,
            content=content
        )

        logger.debug(f"Agent {self.name} sending message to {target_agent}: {message_type}")
        return message

    async def receive_message(self, message: AgentMessage):
        """接收消息"""
        await self.message_queue.put(message)
        logger.debug(f"Agent {self.name} received message from {message.sender}: {message.message_type}")

    async def process_messages(self):
        """处理消息队列"""
        while self.is_active:
            try:
                message = await asyncio.wait_for(self.message_queue.get(), timeout=1.0)
                await self.handle_message(message)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Agent {self.name} error processing message: {e}")

    @abstractmethod
    async def handle_message(self, message: AgentMessage) -> Optional[AgentMessage]:
        """处理接收到的消息"""
        pass

    @abstractmethod
    async def execute_task(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """执行具体任务"""
        pass

    def update_performance_stats(self, response_time: float, success: bool):
        """更新性能统计"""
        self.tasks_completed += 1
        if not success:
            self.tasks_failed += 1

        # 更新平均响应时间
        if self.tasks_completed == 1:
            self.average_response_time = response_time
        else:
            self.average_response_time = (
                (self.average_response_time * (self.tasks_completed - 1)) + response_time
            ) / self.tasks_completed

    def get_performance_stats(self) -> Dict[str, Any]:
        """获取性能统计"""
        return {
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "success_rate": (self.tasks_completed - self.tasks_failed) / max(self.tasks_completed, 1),
            "average_response_time": self.average_response_time,
            "state": self.state
        }

    def __str__(self):
        return f"Agent(name={self.name}, expertise={self.expertise}, state={self.state})"
