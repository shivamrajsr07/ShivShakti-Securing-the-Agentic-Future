from urllib.parse import urlparse
from app.models.security import BrowserVisit, Decision, EventType, SecurityEvent, Severity


APPROVED_DOMAINS = {"learn.microsoft.com", "azure.microsoft.com", "github.com", "openai.com", "microsoft.com"}
PHISHING_HINTS = ["login-verify", "secure-update", "microsoft-support", "account-reset", "credential", "free-gift"]
DANGEROUS_EXTENSIONS = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs")


def inspect_browser_visit(visit: BrowserVisit) -> SecurityEvent:
    parsed = urlparse(visit.url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()

    if not parsed.scheme.startswith("http") or not host:
        return SecurityEvent(
            type=EventType.browser,
            title="Malformed navigation blocked",
            severity=Severity.medium,
            decision=Decision.blocked,
            agent_id=visit.agent_id,
            rule="BROWSER-MALFORMED-URL",
            confidence=0.94,
            summary="The browser target is not a valid HTTP or HTTPS URL.",
            mitigation="Normalize navigation through the browser sandbox URL parser.",
            metadata=visit.model_dump(),
        )

    if any(path.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
        return SecurityEvent(
            type=EventType.browser,
            title="Dangerous download blocked",
            severity=Severity.critical,
            decision=Decision.blocked,
            agent_id=visit.agent_id,
            rule="BROWSER-DOWNLOAD-EXECUTABLE",
            confidence=0.98,
            summary="Navigation attempted to retrieve an executable or script payload.",
            mitigation="Download only through malware scanning and human approval workflows.",
            metadata=visit.model_dump(),
        )

    if any(hint in host or hint in path for hint in PHISHING_HINTS):
        return SecurityEvent(
            type=EventType.browser,
            title="Phishing navigation blocked",
            severity=Severity.high,
            decision=Decision.blocked,
            agent_id=visit.agent_id,
            rule="BROWSER-PHISHING-HEURISTIC",
            confidence=0.89,
            summary="The destination resembles a credential harvesting or brand impersonation URL.",
            mitigation="Verify domain ownership and use an approved-domain navigation policy.",
            metadata=visit.model_dump(),
        )

    decision = Decision.allowed if host in APPROVED_DOMAINS or host.endswith(".microsoft.com") else Decision.review_required
    return SecurityEvent(
        type=EventType.browser,
        title="Browser navigation reviewed",
        severity=Severity.low if decision == Decision.allowed else Severity.medium,
        decision=decision,
        agent_id=visit.agent_id,
        rule="BROWSER-DOMAIN-POLICY",
        confidence=0.86,
        summary="Destination was evaluated against phishing, download, and domain policies.",
        mitigation="Use approved domains for autonomous browsing; require approval for external destinations.",
        metadata={**visit.model_dump(), "host": host, "approved": decision == Decision.allowed},
    )

