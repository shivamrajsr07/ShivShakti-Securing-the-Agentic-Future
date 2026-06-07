import ipaddress
import re
from urllib.parse import urlparse

from app.models.security import Decision, EventType, SecurityEvent, Severity


IP_CANDIDATE = re.compile(r"(?<![\w:])(?:\d{1,3}\.){3}\d{1,3}(?![\w:])|(?<![\w])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w])")
URL_CANDIDATE = re.compile(r"https?://[^\s'\"<>]+", re.I)
SUSPICIOUS_PORTS = {21, 22, 23, 25, 3389, 4444, 5900, 8080, 8443}
RISKY_PATH_HINTS = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs", "/login", "/admin", "/shell")


def _classify_ip(value: str) -> dict:
    address = ipaddress.ip_address(value.strip("[]"))
    flags = []
    risk = 0

    if address.is_loopback:
        flags.append("loopback")
        risk += 35
    if address.is_private:
        flags.append("private")
        risk += 22
    if address.is_link_local:
        flags.append("link-local")
        risk += 18
    if address.is_multicast:
        flags.append("multicast")
        risk += 16
    if address.is_reserved:
        flags.append("reserved")
        risk += 12
    if address.is_global:
        flags.append("public")
        risk += 8

    return {"ip": str(address), "version": address.version, "flags": flags or ["unremarkable"], "risk": risk}


def inspect_network_indicators(content: str, agent_id: str) -> SecurityEvent:
    findings = []

    for match in IP_CANDIDATE.findall(content):
        try:
            findings.append(_classify_ip(match))
        except ValueError:
            continue

    for raw_url in URL_CANDIDATE.findall(content):
        parsed = urlparse(raw_url)
        host = parsed.hostname or ""
        url_risk = 0
        url_flags = []

        try:
            host_finding = _classify_ip(host)
            url_risk += host_finding["risk"] + 14
            url_flags.extend([f"ip-host:{flag}" for flag in host_finding["flags"]])
        except ValueError:
            if any(part in host.lower() for part in ("login-verify", "account-reset", "secure-update", "credential")):
                url_risk += 36
                url_flags.append("phishing-name")

        if parsed.port in SUSPICIOUS_PORTS:
            url_risk += 24
            url_flags.append(f"suspicious-port:{parsed.port}")
        if parsed.scheme != "https":
            url_risk += 12
            url_flags.append("cleartext-http")
        if parsed.path.lower().endswith(RISKY_PATH_HINTS):
            url_risk += 38
            url_flags.append("risky-path")

        if url_flags:
            findings.append({"url": raw_url, "host": host, "flags": url_flags, "risk": url_risk})

    total_risk = min(100, sum(item["risk"] for item in findings))
    if total_risk >= 70:
        severity = Severity.critical
        decision = Decision.blocked
        title = "High-risk network indicator blocked"
    elif total_risk >= 38:
        severity = Severity.high
        decision = Decision.review_required
        title = "Suspicious network indicator requires review"
    elif findings:
        severity = Severity.medium
        decision = Decision.review_required
        title = "Network indicators reviewed"
    else:
        severity = Severity.low
        decision = Decision.allowed
        title = "Network content cleared"

    if findings:
        summary = f"Detected {len(findings)} IP or URL network indicators with risk score {total_risk}/100."
        mitigation = "Block autonomous connections until ownership, protocol, port, and destination reputation are verified."
    else:
        summary = "No IPv4, IPv6, or URL network indicators were found in the submitted content."
        mitigation = "Continue scanning prompts, browser targets, and tool payloads before network access."

    return SecurityEvent(
        type=EventType.network,
        title=title,
        severity=severity,
        decision=decision,
        agent_id=agent_id,
        rule="NETWORK-INDICATOR-INTEL",
        confidence=0.91 if findings else 0.88,
        summary=summary,
        mitigation=mitigation,
        metadata={"findings": findings[:20], "preview": content[:240], "risk_score": total_risk},
    )
