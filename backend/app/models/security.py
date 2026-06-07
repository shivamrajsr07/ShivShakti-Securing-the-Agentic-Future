from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field
from typing import Any
from uuid import uuid4


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Decision(str, Enum):
    allowed = "allowed"
    blocked = "blocked"
    review_required = "review_required"


class EventType(str, Enum):
    prompt = "prompt"
    credential = "credential"
    tool = "tool"
    browser = "browser"
    network = "network"
    identity = "identity"
    system = "system"


class SecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    type: EventType
    title: str
    severity: Severity
    decision: Decision
    agent_id: str | None = None
    rule: str
    confidence: float = Field(ge=0, le=1)
    summary: str
    mitigation: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentRole(str, Enum):
    planner = "planner"
    browser = "browser"
    executor = "executor"
    analyst = "analyst"


class AgentIdentity(BaseModel):
    agent_id: str
    display_name: str
    role: AgentRole
    permissions: list[str]
    trust_score: int = Field(ge=0, le=100)
    signed_session_token: str
    status: str = "verified"


class ToolInvocation(BaseModel):
    agent_id: str
    tool_name: str
    action: str
    target: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class BrowserVisit(BaseModel):
    agent_id: str
    url: str
    referrer: str | None = None
