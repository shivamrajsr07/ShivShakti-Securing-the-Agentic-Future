from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.config import get_settings
from app.models.security import BrowserVisit, ToolInvocation
from app.schemas.security import BrowserScanRequest, CredentialScanRequest, DemoAttackRequest, HealthResponse, NetworkScanRequest, PromptScanRequest
from app.security.browser_guard import inspect_browser_visit
from app.security.credential_guard import CredentialLeakPrevention
from app.security.network_guard import inspect_network_indicators
from app.security.prompt_guard import PromptInjectionShield
from app.security.rbac import list_agents, verify_tool_invocation
from app.services.audit_service import audit_service
from app.services.browser_sandbox import sandbox_visit
from app.services.demo_service import simulate_attack
from app.websocket.manager import manager


router = APIRouter()
prompt_guard = PromptInjectionShield()
credential_guard = CredentialLeakPrevention()


async def record_and_emit(event):
    audit_service.record(event)
    await manager.broadcast(event)
    return event


@router.get("/health", response_model=HealthResponse)
def health():
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        service=settings.app_name,
        checks={"database": "ready", "websocket": "ready", "policy_engine": "ready"},
    )


@router.get("/agents")
def agents():
    return list_agents()


@router.get("/events")
def events(limit: int = 50):
    return audit_service.recent(limit)


@router.get("/analytics")
def analytics():
    return audit_service.analytics()


@router.post("/scan/prompt")
async def scan_prompt(request: PromptScanRequest):
    return await record_and_emit(prompt_guard.scan(request.prompt, request.agent_id))


@router.post("/scan/credentials")
async def scan_credentials(request: CredentialScanRequest):
    return await record_and_emit(credential_guard.scan(request.content, request.agent_id))


@router.post("/guard/tool")
async def guard_tool(invocation: ToolInvocation):
    return await record_and_emit(verify_tool_invocation(invocation))


@router.post("/guard/browser")
async def guard_browser(request: BrowserScanRequest):
    return await record_and_emit(inspect_browser_visit(BrowserVisit(agent_id=request.agent_id, url=request.url)))


@router.post("/scan/network")
async def scan_network(request: NetworkScanRequest):
    return await record_and_emit(inspect_network_indicators(request.content, request.agent_id))


@router.post("/browser/sandbox")
async def browser_sandbox(request: BrowserScanRequest):
    result = await sandbox_visit(BrowserVisit(agent_id=request.agent_id, url=request.url))
    result["event"] = await record_and_emit(result["event"])
    return result


@router.post("/demo/simulate")
async def demo_simulate(request: DemoAttackRequest):
    return await record_and_emit(simulate_attack(request.attack_type))


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
