from pydantic import BaseModel, Field
from typing import Any


class PromptScanRequest(BaseModel):
    agent_id: str = "planner-01"
    prompt: str = Field(min_length=1)


class CredentialScanRequest(BaseModel):
    agent_id: str = "executor-01"
    content: str = Field(min_length=1)


class BrowserScanRequest(BaseModel):
    agent_id: str = "browser-01"
    url: str = Field(min_length=4)


class NetworkScanRequest(BaseModel):
    agent_id: str = "analyst-01"
    content: str = Field(min_length=1)


class DemoAttackRequest(BaseModel):
    attack_type: str


class HealthResponse(BaseModel):
    status: str
    service: str
    checks: dict[str, Any]
