"""
Link Safety - Check URLs for safety before clicking or sharing.

Moltbook-specific risks addressed:
- Malicious links disguised as legitimate
- Redirect chains hiding true destination
- Phishing links mimicking Moltbook
- Credential harvesting URLs
- Tracking/fingerprinting links

This module validates URLs before your agent interacts with them.
"""

import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class LinkCheckResult:
    """Result of link safety check."""
    is_safe: bool
    risk_level: str  # "none", "low", "medium", "high"
    url: str
    final_domain: str
    warnings: List[str]
    recommendation: str


class LinkSafety:
    """
    Check URLs for safety before interacting.

    Validates:
    - Domain reputation
    - Redirect patterns
    - Phishing indicators
    - Suspicious URL parameters
    - Known malicious patterns

    Usage:
        checker = LinkSafety()

        # Before clicking or sharing a link
        result = checker.check_url(url)
        if not result.is_safe:
            # Don't interact with this link
    """

    # Trusted domains (add your own)
    TRUSTED_DOMAINS = {
        "moltbook.com",
        "www.moltbook.com",
        "docs.moltbook.com",
        "github.com",
        "wikipedia.org",
        "arxiv.org",
    }

    # Known malicious patterns
    MALICIOUS_PATTERNS = [
        r"bit\.ly/",       # URL shorteners (hide destination)
        r"tinyurl\.com/",
        r"t\.co/",
        r"goo\.gl/",
        r"ow\.ly/",
        r"is\.gd/",
        r"buff\.ly/",
        r"rebrand\.ly/",

        r"discord\.gift/",     # Fake Discord nitro
        r"discordgift\.",
        r"steam.*community.*login",  # Steam phishing
        r"paypa[l1].*verify",  # PayPal phishing

        # Common phishing patterns
        r"login.*verify",
        r"account.*suspend",
        r"security.*alert",
        r"update.*billing",

        # Data exfiltration
        r"webhook\.",
        r"requestbin\.",
        r"ngrok\.io",
        r"pipedream\.net",
    ]

    # Suspicious URL parameters
    SUSPICIOUS_PARAMS = [
        "redirect",
        "return",
        "goto",
        "url",
        "link",
        "target",
        "callback",
        "next",
        "continue",
        "returnTo",
    ]

    # Phishing domain patterns (typosquatting)
    PHISHING_PATTERNS = {
        "moltbook": [
            r"m[o0]ltb[o0][o0]k",  # Letter substitution
            r"moltbok",            # Missing letter
            r"molltbook",          # Extra letter
            r"moltbook[.-]\w+",    # Subdomain tricks
        ],
        "google": [r"g[o0][o0]gle", r"gooogle", r"googIe"],
        "facebook": [r"faceb[o0][o0]k", r"facebok", r"faceboook"],
    }

    def __init__(self, additional_trusted: Set[str] = None):
        """
        Initialize link safety checker.

        Args:
            additional_trusted: Additional domains to trust
        """
        self.trusted = set(self.TRUSTED_DOMAINS)
        if additional_trusted:
            self.trusted.update(additional_trusted)

        # Compile patterns
        self._malicious = [re.compile(p, re.IGNORECASE) for p in self.MALICIOUS_PATTERNS]
        self._phishing = {
            brand: [re.compile(p, re.IGNORECASE) for p in patterns]
            for brand, patterns in self.PHISHING_PATTERNS.items()
        }

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower().split(':')[0]  # Remove port
        except Exception:
            return ""

    def _check_typosquatting(self, domain: str) -> Optional[str]:
        """Check if domain is typosquatting a known brand."""
        for brand, patterns in self._phishing.items():
            for pattern in patterns:
                if pattern.search(domain) and brand not in domain:
                    return brand
        return None

    def _check_suspicious_params(self, url: str) -> List[str]:
        """Check for suspicious URL parameters."""
        suspicious = []
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            for param in params:
                if param.lower() in self.SUSPICIOUS_PARAMS:
                    value = params[param][0] if params[param] else ""
                    # Check if parameter contains another URL
                    if re.match(r'https?://', value):
                        suspicious.append(f"Parameter '{param}' contains redirect URL")

        except Exception:
            pass

        return suspicious

    def _check_path_tricks(self, url: str) -> List[str]:
        """Check for path-based tricks."""
        warnings = []
        try:
            parsed = urlparse(url)
            path = unquote(parsed.path)

            # Check for @ in path (credential harvesting attempt)
            if '@' in path:
                warnings.append("URL contains @ symbol in path")

            # Check for double encoding
            if '%25' in url:
                warnings.append("URL contains double-encoded characters")

            # Check for path traversal
            if '../' in path or '..\\' in path:
                warnings.append("URL contains path traversal")

            # Check for hidden extensions
            if re.search(r'\.(exe|bat|cmd|ps1|sh|js|vbs)\b', path, re.IGNORECASE):
                warnings.append("URL points to executable file")

        except Exception:
            pass

        return warnings

    def check_url(self, url: str) -> LinkCheckResult:
        """
        Check if a URL is safe.

        Args:
            url: The URL to check

        Returns:
            LinkCheckResult with analysis
        """
        if not url:
            return LinkCheckResult(
                is_safe=False,
                risk_level="high",
                url=url,
                final_domain="",
                warnings=["Empty URL"],
                recommendation="Do not interact"
            )

        # Ensure URL has scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        domain = self._extract_domain(url)
        warnings = []

        # 1. Check trusted domains
        is_trusted = any(
            domain == trusted or domain.endswith('.' + trusted)
            for trusted in self.trusted
        )

        # 2. Check malicious patterns
        for pattern in self._malicious:
            if pattern.search(url):
                warnings.append(f"URL matches malicious pattern")
                break

        # 3. Check typosquatting
        typosquat_brand = self._check_typosquatting(domain)
        if typosquat_brand:
            warnings.append(f"Domain may be impersonating {typosquat_brand}")

        # 4. Check suspicious parameters
        param_warnings = self._check_suspicious_params(url)
        warnings.extend(param_warnings)

        # 5. Check path tricks
        path_warnings = self._check_path_tricks(url)
        warnings.extend(path_warnings)

        # 6. Check for IP address instead of domain
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            warnings.append("URL uses IP address instead of domain")

        # 7. Check for non-standard ports
        try:
            parsed = urlparse(url)
            if parsed.port and parsed.port not in [80, 443]:
                warnings.append(f"URL uses non-standard port: {parsed.port}")
        except Exception:
            pass

        # 8. Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.cc']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            warnings.append("URL uses suspicious top-level domain")

        # Determine risk level
        if is_trusted and not warnings:
            risk_level = "none"
            is_safe = True
            recommendation = "URL appears safe"
        elif warnings and any("malicious" in w.lower() or "impersonating" in w.lower() for w in warnings):
            risk_level = "high"
            is_safe = False
            recommendation = "Do not interact with this URL"
        elif warnings:
            risk_level = "medium"
            is_safe = False
            recommendation = "Exercise caution with this URL"
        elif not is_trusted:
            risk_level = "low"
            is_safe = True
            recommendation = "URL is not from a trusted domain"
        else:
            risk_level = "none"
            is_safe = True
            recommendation = "URL appears safe"

        return LinkCheckResult(
            is_safe=is_safe,
            risk_level=risk_level,
            url=url,
            final_domain=domain,
            warnings=warnings,
            recommendation=recommendation
        )

    def extract_urls(self, text: str) -> List[str]:
        """
        Extract all URLs from text.

        Args:
            text: Text to scan

        Returns:
            List of URLs found
        """
        # URL regex pattern
        url_pattern = r'https?://[^\s<>\[\]{}|\\^`"\']+|www\.[^\s<>\[\]{}|\\^`"\']+\.[a-z]{2,}'
        return re.findall(url_pattern, text, re.IGNORECASE)

    def check_all_urls(self, text: str) -> Dict[str, LinkCheckResult]:
        """
        Check all URLs in a text.

        Args:
            text: Text containing URLs

        Returns:
            Dict mapping URL to check result
        """
        urls = self.extract_urls(text)
        return {url: self.check_url(url) for url in urls}

    def add_trusted_domain(self, domain: str):
        """Add a domain to the trusted list."""
        self.trusted.add(domain.lower())

    def remove_trusted_domain(self, domain: str):
        """Remove a domain from the trusted list."""
        self.trusted.discard(domain.lower())


# Global instance
_link_safety: Optional[LinkSafety] = None


def get_link_safety() -> LinkSafety:
    """Get or create the global link safety checker."""
    global _link_safety
    if _link_safety is None:
        _link_safety = LinkSafety()
    return _link_safety


def check_url(url: str) -> LinkCheckResult:
    """Check if a URL is safe."""
    return get_link_safety().check_url(url)


def check_text_for_urls(text: str) -> Dict[str, LinkCheckResult]:
    """Check all URLs in text."""
    return get_link_safety().check_all_urls(text)
