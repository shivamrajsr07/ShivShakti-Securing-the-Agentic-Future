import re
from app.models.security import Decision, EventType, SecurityEvent, Severity


class CredentialLeakPrevention:
    def __init__(self) -> None:
        self.patterns: list[tuple[str, re.Pattern[str]]] = [
            ("SECRET-OPENAI", re.compile(r"sk-[A-Za-z0-9_\-]{20,}")),
            ("SECRET-AWS", re.compile(r"AKIA[0-9A-Z]{16}")),
            ("SECRET-JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{15,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
            ("SECRET-PASSWORD", re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{8,}")),
            ("SECRET-CONNECTION-STRING", re.compile(r"(?i)(postgres|mysql|mongodb|redis)://[^@\s]+:[^@\s]+@[^ \n]+")),
        ]

    def mask(self, content: str) -> str:
        masked = content
        for _, pattern in self.patterns:
            masked = pattern.sub("[REDACTED_SECRET]", masked)
        return masked

    def scan(self, content: str, agent_id: str) -> SecurityEvent:
        hits = [name for name, pattern in self.patterns if pattern.search(content)]
        if not hits:
            return SecurityEvent(
                type=EventType.credential,
                title="Outbound content cleared",
                severity=Severity.low,
                decision=Decision.allowed,
                agent_id=agent_id,
                rule="SECRET-CLEAN",
                confidence=0.94,
                summary="No credential-like material found in outbound content.",
                mitigation="Keep masking enabled for all external channels.",
                metadata={"masked_preview": content[:220]},
            )

        return SecurityEvent(
            type=EventType.credential,
            title="Credential leak blocked",
            severity=Severity.critical,
            decision=Decision.blocked,
            agent_id=agent_id,
            rule="SECRET-EXFILTRATION",
            confidence=0.97,
            summary=f"Detected sensitive material matching {', '.join(hits)}.",
            mitigation="Rotate exposed credentials, remove secrets from agent context, and retry with redacted data.",
            metadata={"detectors": hits, "masked_preview": self.mask(content)[:220]},
        )

