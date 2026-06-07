from jose import jwt
from app.core.config import get_settings
from app.models.security import AgentIdentity, AgentRole, Decision, EventType, SecurityEvent, Severity, ToolInvocation


ROLE_PERMISSIONS = {
    AgentRole.planner: ["plan:create", "docs:read"],
    AgentRole.browser: ["web:browse:approved", "docs:read"],
    AgentRole.executor: ["workflow:execute:safe", "docs:read"],
    AgentRole.analyst: ["audit:read", "threats:read", "docs:read"],
}

AGENTS: dict[str, dict] = {
    "planner-01": {"display_name": "Planner Agent", "role": AgentRole.planner, "trust_score": 92},
    "browser-01": {"display_name": "Browser Agent", "role": AgentRole.browser, "trust_score": 84},
    "executor-01": {"display_name": "Executor Agent", "role": AgentRole.executor, "trust_score": 78},
    "analyst-01": {"display_name": "Security Analyst Agent", "role": AgentRole.analyst, "trust_score": 96},
}

SAFE_TOOLS = {
    "docs.read": {"actions": ["read", "search"], "permission": "docs:read"},
    "browser.navigate": {"actions": ["open", "inspect"], "permission": "web:browse:approved"},
    "workflow.run": {"actions": ["run_safe_workflow"], "permission": "workflow:execute:safe"},
    "audit.query": {"actions": ["list", "detail"], "permission": "audit:read"},
}

HIGH_RISK_ACTIONS = ["delete", "drop", "transfer", "wire", "download_executable", "disable_security", "export_secrets"]


def sign_agent_session(agent_id: str, role: AgentRole) -> str:
    settings = get_settings()
    return jwt.encode({"sub": agent_id, "role": role.value, "issuer": "shivshakti"}, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def list_agents() -> list[AgentIdentity]:
    identities: list[AgentIdentity] = []
    for agent_id, data in AGENTS.items():
        role = data["role"]
        identities.append(
            AgentIdentity(
                agent_id=agent_id,
                display_name=data["display_name"],
                role=role,
                permissions=ROLE_PERMISSIONS[role],
                trust_score=data["trust_score"],
                signed_session_token=sign_agent_session(agent_id, role),
            )
        )
    return identities


def verify_tool_invocation(invocation: ToolInvocation) -> SecurityEvent:
    agent = next((item for item in list_agents() if item.agent_id == invocation.agent_id), None)
    if agent is None:
        return SecurityEvent(
            type=EventType.identity,
            title="Unknown agent blocked",
            severity=Severity.high,
            decision=Decision.blocked,
            agent_id=invocation.agent_id,
            rule="IDENTITY-UNKNOWN",
            confidence=0.99,
            summary="Tool invocation came from an unregistered agent identity.",
            mitigation="Issue a signed session token from the identity broker before allowing tool access.",
            metadata=invocation.model_dump(),
        )

    action_text = f"{invocation.tool_name}:{invocation.action}:{invocation.target or ''}".lower()
    if any(risk in action_text for risk in HIGH_RISK_ACTIONS):
        return SecurityEvent(
            type=EventType.tool,
            title="Unsafe tool invocation blocked",
            severity=Severity.critical,
            decision=Decision.blocked,
            agent_id=invocation.agent_id,
            rule="TOOL-HIGH-RISK-ACTION",
            confidence=0.96,
            summary="The requested action can destroy data, transfer value, execute malware, or expose secrets.",
            mitigation="Require human approval, use a constrained workflow, and verify target scope before retrying.",
            metadata=invocation.model_dump(),
        )

    tool_policy = SAFE_TOOLS.get(invocation.tool_name)
    if tool_policy is None or invocation.action not in tool_policy["actions"]:
        return SecurityEvent(
            type=EventType.tool,
            title="Unapproved tool blocked",
            severity=Severity.high,
            decision=Decision.blocked,
            agent_id=invocation.agent_id,
            rule="TOOL-NOT-ALLOWLISTED",
            confidence=0.91,
            summary="The tool or action is not present in the security allowlist.",
            mitigation="Register the tool with explicit allowed actions and least-privilege permissions.",
            metadata=invocation.model_dump(),
        )

    required_permission = tool_policy["permission"]
    if required_permission not in agent.permissions:
        return SecurityEvent(
            type=EventType.tool,
            title="RBAC policy blocked action",
            severity=Severity.medium,
            decision=Decision.blocked,
            agent_id=invocation.agent_id,
            rule="RBAC-PERMISSION-DENIED",
            confidence=0.93,
            summary=f"{agent.display_name} lacks {required_permission}.",
            mitigation="Route the task to an agent with the correct role or request just-in-time approval.",
            metadata=invocation.model_dump(),
        )

    return SecurityEvent(
        type=EventType.tool,
        title="Tool invocation allowed",
        severity=Severity.low,
        decision=Decision.allowed,
        agent_id=invocation.agent_id,
        rule="TOOL-ALLOWLIST-PASS",
        confidence=0.95,
        summary="Tool, action, identity, and permissions passed policy checks.",
        mitigation="Continue monitoring outputs for credential leakage and suspicious browser pivots.",
        metadata=invocation.model_dump(),
    )

