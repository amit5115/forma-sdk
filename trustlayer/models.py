from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class StepType(str, Enum):
    LLM = "llm"
    TOOL = "tool"
    INPUT = "input"
    OUTPUT = "output"
    DECISION = "decision"


class RunStatus(str, Enum):
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SELF_HEALED = "self_healed"


@dataclass
class TraceStep:
    step_number: int
    step_type: StepType
    label: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    model: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    cost_usd: Optional[float] = None
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    tool_result: Optional[Any] = None
    status: str = "success"
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "step_type": self.step_type.value,
            "label": self.label,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_ms": self.duration_ms,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "cost_usd": self.cost_usd,
            "tool_name": self.tool_name,
            "tool_args": self.tool_args,
            "status": self.status,
            "error": self.error,
            "metadata": self.metadata,
        }


@dataclass
class AgentRun:
    run_id: str
    agent_name: str
    agent_version: str
    started_at: datetime
    human_sponsor: Optional[str] = None   # auto-filled server-side from account email
    ended_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    status: RunStatus = RunStatus.RUNNING
    steps: List[TraceStep] = field(default_factory=list)
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    input_data: Optional[Any] = None
    output_data: Optional[Any] = None
    error: Optional[str] = None
    signature: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "agent_name": self.agent_name,
            "agent_version": self.agent_version,
            "human_sponsor": self.human_sponsor,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_ms": self.duration_ms,
            "status": self.status.value,
            "steps": [s.to_dict() for s in self.steps],
            "total_tokens": self.total_tokens,
            "total_cost_usd": self.total_cost_usd,
            "error": self.error,
            "signature": self.signature,
            "metadata": self.metadata,
        }
