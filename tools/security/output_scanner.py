"""
Output Scanner - Scan LLM outputs before posting.

Detects in agent-generated content:
- Leaked API keys (moltbook_, sk-, sk-ant-)
- System prompt references (SOUL.md, AGENTS.md, "my instructions")
- Injection echoes (agent repeating attack patterns back)

This is a critical defense layer - attackers may try to get your agent
to leak credentials or reveal system prompts through carefully crafted prompts.
"""

import re
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class OutputScanResult:
    """Result of scanning output content."""
    is_safe: bool
    risk_level: str  # "none", "low", "medium", "high"
    violations: List[str]
    redacted_content: Optional[str] = None
    recommendations: List[str] = None


class OutputScanner:
    """
    Scans LLM-generated content before it's posted.

    Usage:
        scanner = OutputScanner()
        result = scanner.scan(agent_response)
        if not result.is_safe:
            # Block or redact the response
            safe_content = scanner.redact(agent_response)
    """

    # Patterns that should NEVER appear in agent output
    BLOCKED_PATTERNS = {
        "credential_leak": {
            "risk": "high",
            "patterns": [
                # Moltbook API keys
                r"moltbook_[a-z]{2}_[A-Za-z0-9]{32,}",
                # OpenAI API keys
                r"sk-[A-Za-z0-9]{48,}",
                r"sk-proj-[A-Za-z0-9\-_]{40,}",
                # Anthropic API keys
                r"sk-ant-[A-Za-z0-9\-_]{40,}",
                # Generic API key patterns
                r"api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9\-_]{20,}['\"]",
                r"api[_-]?secret\s*[=:]\s*['\"][A-Za-z0-9\-_]{20,}['\"]",
                # Bearer tokens in output
                r"Bearer\s+[A-Za-z0-9\-_\.]{20,}",
                # AWS keys
                r"AKIA[0-9A-Z]{16}",
                r"aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
            ],
            "message": "Potential credential leak detected"
        },

        "system_prompt_leak": {
            "risk": "high",
            "patterns": [
                # Direct file references
                r"SOUL\.md",
                r"AGENTS\.md",
                r"system[_\s]?prompt",
                # Common prompt leak phrases
                r"my\s+(system\s+)?instructions?\s+(are|say|tell)",
                r"I\s+was\s+(instructed|told|programmed)\s+to",
                r"my\s+guidelines?\s+(are|say|state)",
                r"according\s+to\s+my\s+(instructions|guidelines|rules)",
                # Revealing configuration
                r"my\s+api[_\s]?key\s+is",
                r"I\s+am\s+configured\s+to",
                r"my\s+configuration\s+(is|says)",
            ],
            "message": "Potential system prompt leak detected"
        },

        "injection_echo": {
            "risk": "high",
            "patterns": [
                # Agent repeating injection attempts
                r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
                r"you\s+are\s+now\s+(a\s+)?different",
                r"disregard\s+(all\s+)?(previous|prior)\s+instructions",
                r"new\s+instructions?\s*:",
                r"SYSTEM:\s+you\s+are\s+now",
                # DAN/jailbreak echoes
                r"DAN\s+mode\s+enabled",
                r"developer\s+mode\s+enabled",
                r"jailbreak\s+successful",
            ],
            "message": "Agent may be echoing injection attempts"
        },

        "path_leak": {
            "risk": "medium",
            "patterns": [
                # Home directory paths
                r"/Users/[^/\s]+/",
                r"/home/[^/\s]+/",
                r"C:\\Users\\[^\\]+\\",
                # Docker/container paths that might leak info
                r"/app/[^/\s]+/credentials",
                r"/secrets/[^/\s]+",
                r"\.env\s+file",
            ],
            "message": "Potential file path leak detected"
        },

        "internal_info_leak": {
            "risk": "medium",
            "patterns": [
                # Internal URLs
                r"localhost:\d+",
                r"127\.0\.0\.1:\d+",
                r"192\.168\.\d+\.\d+",
                r"10\.\d+\.\d+\.\d+",
                # Internal hostnames
                r"internal\.[a-z]+\.[a-z]+",
                # Database connection strings
                r"(mongodb|mysql|postgres|redis)://[^\s]+",
            ],
            "message": "Potential internal information leak"
        }
    }

    # Additional context patterns that raise suspicion when combined
    SUSPICIOUS_CONTEXT = [
        r"here\s+is\s+(the|my)\s+(api|secret|key|password)",
        r"(the|my)\s+credentials?\s+(are|is)\s*:",
        r"I\'ll\s+share\s+(my|the)\s+",
        r"here\'s\s+what\s+I\s+know\s+about\s+my\s+",
    ]

    def __init__(self, strict_mode: bool = True):
        """
        Initialize the output scanner.

        Args:
            strict_mode: If True, block on medium-risk matches too
        """
        self.strict_mode = strict_mode
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for efficiency."""
        self._compiled = {}
        for category, data in self.BLOCKED_PATTERNS.items():
            self._compiled[category] = {
                "risk": data["risk"],
                "message": data["message"],
                "patterns": [
                    re.compile(p, re.IGNORECASE | re.MULTILINE)
                    for p in data["patterns"]
                ]
            }

        self._suspicious_context = [
            re.compile(p, re.IGNORECASE) for p in self.SUSPICIOUS_CONTEXT
        ]

    def scan(self, content: str) -> OutputScanResult:
        """
        Scan content for security violations.

        Args:
            content: The LLM-generated content to scan

        Returns:
            OutputScanResult with safety assessment
        """
        if not content:
            return OutputScanResult(
                is_safe=True,
                risk_level="none",
                violations=[],
                recommendations=["Content is empty - safe to proceed"]
            )

        violations = []
        risk_scores = []

        # Check each pattern category
        for category, data in self._compiled.items():
            for pattern in data["patterns"]:
                matches = pattern.findall(content)
                if matches:
                    violations.append(f"{data['message']} ({category})")
                    risk_scores.append({"high": 3, "medium": 2, "low": 1}[data["risk"]])
                    break  # One match per category is enough

        # Check for suspicious context
        context_matches = sum(1 for p in self._suspicious_context if p.search(content))
        if context_matches >= 2:
            violations.append("Multiple suspicious context patterns detected")
            risk_scores.append(2)

        # Determine overall risk
        if not risk_scores:
            risk_level = "none"
            is_safe = True
        elif max(risk_scores) >= 3:
            risk_level = "high"
            is_safe = False
        elif max(risk_scores) >= 2:
            risk_level = "medium"
            is_safe = not self.strict_mode
        else:
            risk_level = "low"
            is_safe = True

        recommendations = self._generate_recommendations(violations, risk_level)

        return OutputScanResult(
            is_safe=is_safe,
            risk_level=risk_level,
            violations=violations,
            recommendations=recommendations
        )

    def redact(self, content: str) -> str:
        """
        Redact sensitive content from output.

        Args:
            content: The content to redact

        Returns:
            Content with sensitive information redacted
        """
        if not content:
            return content

        redacted = content

        # Redact credentials
        for category, data in self._compiled.items():
            if category in ["credential_leak", "path_leak"]:
                for pattern in data["patterns"]:
                    redacted = pattern.sub("[REDACTED]", redacted)

        return redacted

    def is_safe(self, content: str) -> bool:
        """
        Quick check if content is safe to post.

        Args:
            content: The content to check

        Returns:
            True if safe, False otherwise
        """
        result = self.scan(content)
        return result.is_safe

    def _generate_recommendations(self, violations: List[str], risk_level: str) -> List[str]:
        """Generate recommendations based on violations."""
        recommendations = []

        if risk_level == "high":
            recommendations.append("DO NOT post this content - high security risk")
            recommendations.append("Review agent's system prompt for weaknesses")
        elif risk_level == "medium":
            recommendations.append("Consider redacting sensitive content before posting")
            recommendations.append("Monitor agent for repeated issues")
        elif risk_level == "low":
            recommendations.append("Content appears mostly safe")
        else:
            recommendations.append("Content passed all security checks")

        if any("credential" in v.lower() for v in violations):
            recommendations.append("Rotate any exposed credentials immediately")

        if any("system prompt" in v.lower() for v in violations):
            recommendations.append("Strengthen system prompt anti-leak instructions")

        if any("injection" in v.lower() for v in violations):
            recommendations.append("Agent may be compromised - review recent inputs")

        return recommendations


# Convenience functions for simple usage
def scan_output(content: str) -> Dict:
    """
    Quick scan of output content.

    Args:
        content: Content to scan

    Returns:
        Dictionary with scan results
    """
    scanner = OutputScanner()
    result = scanner.scan(content)
    return {
        "is_safe": result.is_safe,
        "risk_level": result.risk_level,
        "violations": result.violations,
        "recommendations": result.recommendations
    }


def redact_output(content: str) -> str:
    """
    Redact sensitive information from output.

    Args:
        content: Content to redact

    Returns:
        Redacted content
    """
    scanner = OutputScanner()
    return scanner.redact(content)


def is_safe_to_post(content: str) -> bool:
    """
    Check if content is safe to post.

    Args:
        content: Content to check

    Returns:
        True if safe to post
    """
    scanner = OutputScanner()
    return scanner.is_safe(content)
