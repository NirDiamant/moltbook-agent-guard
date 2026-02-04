"""
Credential Monitor - Detect Theft Attempts.

Monitor for attempts to access or exfiltrate credentials.
This module watches for:
- Credential patterns in output
- Suspicious memory/file access
- Exfiltration attempts to external endpoints

Based on the Moltbook security incident where 1.5M API keys were exposed.
"""

import re
import time
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class MonitorResult:
    """Result of credential monitoring."""
    is_safe: bool
    alerts: List[str] = field(default_factory=list)
    risk_level: str = "none"  # none, low, medium, high, critical
    matched_patterns: List[str] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class CredentialAlert:
    """A credential security alert."""
    timestamp: str
    alert_type: str
    severity: str
    description: str
    context: Dict = field(default_factory=dict)


class CredentialMonitor:
    """
    Detect credential access and theft attempts.

    Usage:
        monitor = CredentialMonitor()

        # Monitor output before sending
        result = monitor.monitor_output(agent_response)
        if not result.is_safe:
            # Block the response
            print(f"Credential leak detected: {result.alerts}")

        # Monitor memory access
        result = monitor.monitor_memory_access(["ANTHROPIC_API_KEY"])
        if not result.is_safe:
            # Log suspicious access
    """

    # Credential patterns to detect
    CREDENTIAL_PATTERNS = {
        "moltbook_key": {
            "pattern": r"moltbook_[a-z]{2}_[A-Za-z0-9]{32,}",
            "severity": "critical",
            "description": "Moltbook API key"
        },
        "openai_key": {
            "pattern": r"sk-[A-Za-z0-9]{48,}",
            "severity": "critical",
            "description": "OpenAI API key"
        },
        "openai_project_key": {
            "pattern": r"sk-proj-[A-Za-z0-9\-_]{40,}",
            "severity": "critical",
            "description": "OpenAI project key"
        },
        "anthropic_key": {
            "pattern": r"sk-ant-[A-Za-z0-9\-_]{40,}",
            "severity": "critical",
            "description": "Anthropic API key"
        },
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "severity": "critical",
            "description": "AWS access key"
        },
        "aws_secret": {
            "pattern": r"(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            "severity": "critical",
            "description": "AWS secret key"
        },
        "github_token": {
            "pattern": r"ghp_[A-Za-z0-9]{36}",
            "severity": "high",
            "description": "GitHub personal access token"
        },
        "generic_bearer": {
            "pattern": r"Bearer\s+[A-Za-z0-9\-_\.]{20,}",
            "severity": "high",
            "description": "Bearer token"
        },
        "password_field": {
            "pattern": r"(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{4,}['\"]",
            "severity": "high",
            "description": "Password in content"
        },
        "private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            "severity": "critical",
            "description": "Private key"
        },
    }

    # Environment variables to monitor
    SENSITIVE_ENV_VARS = {
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "MOLTBOOK_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SLACK_WEBHOOK_URL",
        "DATABASE_URL",
        "REDIS_URL",
        "SECRET_KEY",
        "JWT_SECRET",
    }

    # Exfiltration indicators
    EXFILTRATION_PATTERNS = [
        r"curl\s+.*?http",
        r"wget\s+.*?http",
        r"requests?\.(get|post)",
        r"fetch\s*\(",
        r"http\.request",
        r"XMLHttpRequest",
    ]

    def __init__(self,
                 alert_on_access: bool = True,
                 max_alerts_per_hour: int = 100):
        """
        Initialize the credential monitor.

        Args:
            alert_on_access: Alert on any sensitive env var access
            max_alerts_per_hour: Max alerts before rate limiting
        """
        self.alert_on_access = alert_on_access
        self.max_alerts_per_hour = max_alerts_per_hour

        # Compile patterns
        self._credential_patterns = {
            name: {
                "compiled": re.compile(data["pattern"], re.IGNORECASE),
                "severity": data["severity"],
                "description": data["description"]
            }
            for name, data in self.CREDENTIAL_PATTERNS.items()
        }

        self._exfiltration_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.EXFILTRATION_PATTERNS
        ]

        # Alert tracking
        self._alerts: List[CredentialAlert] = []
        self._access_counts: Dict[str, int] = defaultdict(int)
        self._alert_times: List[float] = []

    def monitor_output(self, content: str, context: str = "") -> MonitorResult:
        """
        Check if output contains credential patterns.

        Args:
            content: Output content to check
            context: Additional context (e.g., destination)

        Returns:
            MonitorResult with findings
        """
        if not content:
            return MonitorResult(is_safe=True)

        alerts = []
        matched = []
        max_severity = "none"
        severity_order = ["none", "low", "medium", "high", "critical"]

        # Check for credential patterns
        for name, data in self._credential_patterns.items():
            matches = data["compiled"].findall(content)
            if matches:
                severity = data["severity"]
                description = data["description"]

                alerts.append(f"{description} detected in output")
                matched.extend(matches[:3])  # Limit matches shown

                if severity_order.index(severity) > severity_order.index(max_severity):
                    max_severity = severity

                # Log alert
                self._log_alert(
                    "credential_in_output",
                    severity,
                    f"{description} found in output",
                    {"pattern": name, "context": context}
                )

        is_safe = max_severity in ["none", "low"]

        recommendation = ""
        if not is_safe:
            recommendation = "DO NOT send this output - credential leak detected"

        return MonitorResult(
            is_safe=is_safe,
            alerts=alerts,
            risk_level=max_severity,
            matched_patterns=[m[:20] + "..." for m in matched],  # Truncate
            recommendation=recommendation
        )

    def monitor_memory_access(self, accessed_keys: List[str]) -> MonitorResult:
        """
        Alert on suspicious memory/environment access patterns.

        Args:
            accessed_keys: List of keys/variables accessed

        Returns:
            MonitorResult with findings
        """
        alerts = []
        severity = "none"

        sensitive_accessed = []
        for key in accessed_keys:
            if key.upper() in self.SENSITIVE_ENV_VARS:
                sensitive_accessed.append(key)
                self._access_counts[key] += 1

        if sensitive_accessed:
            # Check for unusual access patterns
            unusual = [k for k in sensitive_accessed if self._access_counts[k] > 10]

            if unusual:
                severity = "high"
                alerts.append(f"Excessive access to sensitive keys: {unusual}")
                self._log_alert(
                    "excessive_credential_access",
                    "high",
                    f"Unusual access pattern for: {unusual}",
                    {"access_counts": dict(self._access_counts)}
                )
            elif self.alert_on_access:
                severity = "low"
                alerts.append(f"Sensitive keys accessed: {sensitive_accessed}")

        is_safe = severity in ["none", "low"]

        return MonitorResult(
            is_safe=is_safe,
            alerts=alerts,
            risk_level=severity,
            recommendation="Review access patterns" if not is_safe else ""
        )

    def detect_exfiltration_attempt(self, content: str,
                                    destination: str = "") -> MonitorResult:
        """
        Detect if credentials are being sent externally.

        Args:
            content: Content being sent
            destination: Where it's being sent (URL)

        Returns:
            MonitorResult with findings
        """
        alerts = []
        severity = "none"

        # Check for credentials in content
        cred_result = self.monitor_output(content)

        # Check for exfiltration patterns
        has_network = any(p.search(content) for p in self._exfiltration_patterns)

        # Combined risk assessment
        if cred_result.risk_level == "critical" and (has_network or destination):
            severity = "critical"
            alerts.append("CRITICAL: Credential exfiltration attempt detected")
            self._log_alert(
                "exfiltration_attempt",
                "critical",
                "Credentials being sent to external destination",
                {"destination": destination, "has_network_call": has_network}
            )
        elif cred_result.risk_level in ["high", "critical"]:
            severity = "high"
            alerts.append("Credentials detected in content destined for external")
        elif has_network and destination:
            # Just network activity, no credentials
            severity = "low"

        alerts.extend(cred_result.alerts)

        is_safe = severity in ["none", "low"]

        return MonitorResult(
            is_safe=is_safe,
            alerts=alerts,
            risk_level=severity,
            matched_patterns=cred_result.matched_patterns,
            recommendation="BLOCK immediately" if severity == "critical" else ""
        )

    def _log_alert(self, alert_type: str, severity: str,
                   description: str, context: Dict = None):
        """Log a credential alert."""
        # Rate limiting
        now = time.time()
        hour_ago = now - 3600
        self._alert_times = [t for t in self._alert_times if t > hour_ago]

        if len(self._alert_times) >= self.max_alerts_per_hour:
            return  # Rate limited

        self._alert_times.append(now)

        alert = CredentialAlert(
            timestamp=datetime.utcnow().isoformat(),
            alert_type=alert_type,
            severity=severity,
            description=description,
            context=context or {}
        )

        self._alerts.append(alert)

        # Keep only last 1000 alerts
        if len(self._alerts) > 1000:
            self._alerts = self._alerts[-1000:]

        # Log to standard logger
        if severity == "critical":
            logger.critical(f"CREDENTIAL ALERT: {description}")
        elif severity == "high":
            logger.warning(f"Credential alert: {description}")
        else:
            logger.info(f"Credential monitor: {description}")

    def get_recent_alerts(self, limit: int = 50,
                          min_severity: str = "low") -> List[CredentialAlert]:
        """
        Get recent credential alerts.

        Args:
            limit: Maximum alerts to return
            min_severity: Minimum severity to include

        Returns:
            List of CredentialAlert
        """
        severity_order = ["low", "medium", "high", "critical"]
        min_idx = severity_order.index(min_severity)

        filtered = [
            a for a in self._alerts
            if severity_order.index(a.severity) >= min_idx
        ]

        return filtered[-limit:]

    def get_stats(self) -> Dict:
        """Get credential monitor statistics."""
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)

        for alert in self._alerts:
            severity_counts[alert.severity] += 1
            type_counts[alert.alert_type] += 1

        return {
            "total_alerts": len(self._alerts),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
            "access_counts": dict(self._access_counts),
            "alerts_this_hour": len(self._alert_times),
        }

    def reset_stats(self):
        """Reset monitoring statistics."""
        self._alerts = []
        self._access_counts = defaultdict(int)
        self._alert_times = []


# Global instance
_credential_monitor: Optional[CredentialMonitor] = None


def get_credential_monitor() -> CredentialMonitor:
    """Get or create the global credential monitor."""
    global _credential_monitor
    if _credential_monitor is None:
        _credential_monitor = CredentialMonitor()
    return _credential_monitor


def check_for_credentials(content: str) -> MonitorResult:
    """
    Check content for credential patterns.

    Args:
        content: Content to check

    Returns:
        MonitorResult
    """
    return get_credential_monitor().monitor_output(content)


def detect_exfiltration(content: str, destination: str = "") -> MonitorResult:
    """
    Detect credential exfiltration attempt.

    Args:
        content: Content being sent
        destination: Destination URL

    Returns:
        MonitorResult
    """
    return get_credential_monitor().detect_exfiltration_attempt(content, destination)
