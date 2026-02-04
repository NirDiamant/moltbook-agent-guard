"""
Egress Firewall - Control Agent's External Network Communication.

The "lethal trifecta" includes external communication - this module
controls what URLs your agent can contact.

Features:
- Domain allowlist (only allow specific domains)
- Pattern-based blocking (block known exfiltration endpoints)
- Request logging for audit
- Rate limiting on external requests

Based on Moltbook security research showing attackers use:
- Webhook services for data exfiltration
- Ngrok/tunneling for C2 communication
- RequestBin for credential capture
"""

import re
import time
from urllib.parse import urlparse
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class EgressResult:
    """Result of egress check."""
    allowed: bool
    url: str
    domain: str
    reason: str
    rule_matched: Optional[str] = None


@dataclass
class EgressLog:
    """Log entry for an egress attempt."""
    timestamp: str
    url: str
    domain: str
    allowed: bool
    reason: str
    source: str


class EgressFirewall:
    """
    Control agent's external network communication.

    Usage:
        firewall = EgressFirewall()

        # Check before making request
        result = firewall.check_url(url)
        if result.allowed:
            requests.get(url)
        else:
            logger.warning(f"Blocked: {result.reason}")
    """

    # Default allowed domains (Moltbook + LLM providers)
    DEFAULT_ALLOWED = [
        # Moltbook
        "moltbook.com",
        "www.moltbook.com",
        "api.moltbook.com",
        # LLM providers
        "api.anthropic.com",
        "api.openai.com",
        "generativelanguage.googleapis.com",
        # Groq (for Llama Guard)
        "api.groq.com",
    ]

    # Patterns to block (known exfiltration/C2 endpoints)
    DEFAULT_BLOCKED_PATTERNS = [
        r"webhook\.",           # Generic webhooks
        r"hooks\.slack\.com",   # Slack webhooks (can leak data)
        r"discord\.com/api/webhooks",  # Discord webhooks
        r"ngrok\.io",           # Ngrok tunnels
        r"ngrok\.app",          # New ngrok domains
        r"tunnel\.cloudflare",  # Cloudflare tunnels
        r"requestbin\.",        # Request inspection
        r"pipedream\.net",      # Pipedream (data capture)
        r"hookbin\.com",        # Webhook testing
        r"burpcollaborator\.",  # Burp Suite (pentesting)
        r"interact\.sh",        # Interactsh (OOB testing)
        r"canarytokens\.",      # Canary tokens
        r"dnslog\.",            # DNS logging
        r"oast\.",              # Out-of-band testing
        r"beeceptor\.com",      # API mocking
        r"mockbin\.org",        # Mock endpoints
        r"postb\.in",           # Postbin
        r"paste\.bin",          # Pastebins
        r"pastebin\.com",
        r"hastebin\.com",
        r"0x0\.st",             # File sharing
        r"file\.io",
        r"transfer\.sh",
    ]

    # Block all private/internal IPs
    PRIVATE_IP_PATTERNS = [
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^192\.168\.",
        r"^127\.",
        r"^localhost",
        r"^0\.0\.0\.0",
    ]

    def __init__(self,
                 allowed_domains: List[str] = None,
                 blocked_patterns: List[str] = None,
                 allow_mode: str = "allowlist",
                 log_requests: bool = True,
                 max_requests_per_hour: int = 1000):
        """
        Initialize the egress firewall.

        Args:
            allowed_domains: Domains to allow
            blocked_patterns: Patterns to block
            allow_mode: "allowlist" (only allow specified) or "blocklist" (block specified)
            log_requests: Whether to log all requests
            max_requests_per_hour: Rate limit for external requests
        """
        self.allowed_domains: Set[str] = set(allowed_domains or self.DEFAULT_ALLOWED)
        self.allow_mode = allow_mode
        self.log_requests = log_requests
        self.max_requests_per_hour = max_requests_per_hour

        # Compile blocked patterns
        patterns = blocked_patterns or self.DEFAULT_BLOCKED_PATTERNS
        self._blocked_patterns = [
            re.compile(p, re.IGNORECASE) for p in patterns
        ]

        # Compile private IP patterns
        self._private_ip_patterns = [
            re.compile(p) for p in self.PRIVATE_IP_PATTERNS
        ]

        # Request tracking
        self._request_times: List[float] = []
        self._request_log: List[EgressLog] = []

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower().split(':')[0]  # Remove port
        except Exception:
            return ""

    def _is_private_ip(self, domain: str) -> bool:
        """Check if domain is a private IP."""
        for pattern in self._private_ip_patterns:
            if pattern.match(domain):
                return True
        return False

    def _matches_blocked_pattern(self, url: str, domain: str) -> Optional[str]:
        """Check if URL matches any blocked pattern."""
        for pattern in self._blocked_patterns:
            if pattern.search(url) or pattern.search(domain):
                return pattern.pattern
        return None

    def _check_rate_limit(self) -> bool:
        """Check if within rate limit."""
        now = time.time()
        hour_ago = now - 3600

        # Clean old entries
        self._request_times = [t for t in self._request_times if t > hour_ago]

        return len(self._request_times) < self.max_requests_per_hour

    def check_url(self, url: str, source: str = "unknown") -> EgressResult:
        """
        Check if URL is allowed for agent to contact.

        Args:
            url: URL to check
            source: Source of the request (for logging)

        Returns:
            EgressResult indicating if allowed
        """
        domain = self._extract_domain(url)

        if not domain:
            result = EgressResult(
                allowed=False,
                url=url,
                domain="",
                reason="Invalid URL format"
            )
            self._log_request(url, "", False, result.reason, source)
            return result

        # Check private IPs (always blocked)
        if self._is_private_ip(domain):
            result = EgressResult(
                allowed=False,
                url=url,
                domain=domain,
                reason="Private/internal IP addresses are blocked",
                rule_matched="private_ip"
            )
            self._log_request(url, domain, False, result.reason, source)
            return result

        # Check blocked patterns (always checked)
        blocked_pattern = self._matches_blocked_pattern(url, domain)
        if blocked_pattern:
            result = EgressResult(
                allowed=False,
                url=url,
                domain=domain,
                reason=f"URL matches blocked pattern: {blocked_pattern}",
                rule_matched=blocked_pattern
            )
            self._log_request(url, domain, False, result.reason, source)
            return result

        # Check rate limit
        if not self._check_rate_limit():
            result = EgressResult(
                allowed=False,
                url=url,
                domain=domain,
                reason=f"Rate limit exceeded ({self.max_requests_per_hour}/hour)"
            )
            self._log_request(url, domain, False, result.reason, source)
            return result

        # Check allowlist/blocklist mode
        if self.allow_mode == "allowlist":
            # Only allow explicitly listed domains
            is_allowed = any(
                domain == allowed or domain.endswith('.' + allowed)
                for allowed in self.allowed_domains
            )
            if not is_allowed:
                result = EgressResult(
                    allowed=False,
                    url=url,
                    domain=domain,
                    reason=f"Domain '{domain}' not in allowlist"
                )
                self._log_request(url, domain, False, result.reason, source)
                return result

        # Request is allowed
        self._request_times.append(time.time())
        result = EgressResult(
            allowed=True,
            url=url,
            domain=domain,
            reason="Request allowed"
        )
        self._log_request(url, domain, True, result.reason, source)
        return result

    def _log_request(self, url: str, domain: str, allowed: bool,
                     reason: str, source: str):
        """Log a request attempt."""
        if not self.log_requests:
            return

        entry = EgressLog(
            timestamp=datetime.utcnow().isoformat(),
            url=url[:200],  # Truncate for storage
            domain=domain,
            allowed=allowed,
            reason=reason,
            source=source
        )
        self._request_log.append(entry)

        # Keep only last 1000 entries
        if len(self._request_log) > 1000:
            self._request_log = self._request_log[-1000:]

        # Log blocked requests
        if not allowed:
            logger.warning(f"Egress blocked: {domain} - {reason}")

    def add_allowed_domain(self, domain: str):
        """Add a domain to the allowlist."""
        self.allowed_domains.add(domain.lower())

    def remove_allowed_domain(self, domain: str):
        """Remove a domain from the allowlist."""
        self.allowed_domains.discard(domain.lower())

    def add_blocked_pattern(self, pattern: str):
        """Add a blocked pattern."""
        self._blocked_patterns.append(re.compile(pattern, re.IGNORECASE))

    def get_request_log(self, limit: int = 100,
                        blocked_only: bool = False) -> List[EgressLog]:
        """
        Get recent request log.

        Args:
            limit: Maximum entries to return
            blocked_only: Only return blocked requests

        Returns:
            List of EgressLog entries
        """
        logs = self._request_log
        if blocked_only:
            logs = [l for l in logs if not l.allowed]
        return logs[-limit:]

    def get_stats(self) -> Dict:
        """Get egress firewall statistics."""
        hour_ago = time.time() - 3600
        recent_requests = [t for t in self._request_times if t > hour_ago]

        blocked = sum(1 for l in self._request_log if not l.allowed)
        total = len(self._request_log)

        return {
            "mode": self.allow_mode,
            "allowed_domains": len(self.allowed_domains),
            "blocked_patterns": len(self._blocked_patterns),
            "requests_this_hour": len(recent_requests),
            "rate_limit": self.max_requests_per_hour,
            "total_logged": total,
            "total_blocked": blocked,
            "block_rate": round(blocked / total, 3) if total > 0 else 0
        }

    def reset_stats(self):
        """Reset request tracking."""
        self._request_times = []
        self._request_log = []


# Global instance
_egress_firewall: Optional[EgressFirewall] = None


def get_egress_firewall() -> EgressFirewall:
    """Get or create the global egress firewall."""
    global _egress_firewall
    if _egress_firewall is None:
        _egress_firewall = EgressFirewall()
    return _egress_firewall


def check_egress(url: str, source: str = "unknown") -> EgressResult:
    """
    Check if URL is allowed.

    Args:
        url: URL to check
        source: Request source

    Returns:
        EgressResult
    """
    return get_egress_firewall().check_url(url, source)


def is_url_allowed(url: str) -> bool:
    """
    Quick check if URL is allowed.

    Args:
        url: URL to check

    Returns:
        True if allowed
    """
    return get_egress_firewall().check_url(url).allowed
