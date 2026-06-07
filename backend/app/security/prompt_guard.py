import re
from app.models.security import Decision, EventType, SecurityEvent, Severity


class PromptInjectionShield:
    def __init__(self) -> None:
        self.rules: list[tuple[str, re.Pattern[str], Severity, float, str]] = [
            (
                "PI-IGNORE-INSTRUCTIONS",
                re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|above|system|developer)\b.{0,25}\b(instructions|rules|message)\b", re.I),
                Severity.high,
                0.91,
                "Attempts to override higher-priority instructions.",
            ),
            (
                "PI-SECRET-EXFIL",
                re.compile(r"\b(reveal|print|show|dump|exfiltrate)\b.{0,40}\b(secret|token|api key|password|credential|system prompt)\b", re.I),
                Severity.critical,
                0.96,
                "Requests disclosure of protected secrets or hidden instructions.",
            ),
            (
                "PI-JAILBREAK",
                re.compile(r"\b(jailbreak|developer mode|dan mode|bypass safeguards|no restrictions|system override)\b", re.I),
                Severity.high,
                0.88,
                "Known jailbreak or safeguard bypass phrasing was detected.",
            ),
            (
                "PI-HIDDEN-CONTROL",
                re.compile(r"(<!--.*?(ignore|override|secret).*?-->|base64|rot13|hidden instruction)", re.I | re.S),
                Severity.medium,
                0.74,
                "Potential hidden or encoded instruction channel detected.",
            ),
        ]

    def scan(self, prompt: str, agent_id: str) -> SecurityEvent:
        matches = []
        for rule, pattern, severity, confidence, reason in self.rules:
            if pattern.search(prompt):
                matches.append((rule, severity, confidence, reason))

        if not matches:
            return SecurityEvent(
                type=EventType.prompt,
                title="Prompt accepted",
                severity=Severity.low,
                decision=Decision.allowed,
                agent_id=agent_id,
                rule="PI-CLEAN",
                confidence=0.95,
                summary="No prompt injection indicators were detected.",
                mitigation="Continue monitoring tool calls and downstream browser actions.",
                metadata={"prompt_preview": prompt[:220]},
            )

        rule, severity, confidence, reason = max(matches, key=lambda item: item[2])
        return SecurityEvent(
            type=EventType.prompt,
            title="Prompt injection blocked",
            severity=severity,
            decision=Decision.blocked,
            agent_id=agent_id,
            rule=rule,
            confidence=confidence,
            summary=reason,
            mitigation="Strip attacker instructions, keep only user intent, and re-run under least-privilege agent permissions.",
            metadata={"prompt_preview": prompt[:220], "matches": [m[0] for m in matches]},
        )

