"""
Error Sanitizer - Prevent sensitive data leakage in error messages.

Redacts from error messages:
- API keys (all formats)
- File paths (/Users/xxx/)
- Bearer tokens
- Passwords in JSON
- Connection strings
- Internal hostnames

Error messages often leak sensitive information - this module ensures
that errors sent to logs, Slack, or other destinations are sanitized.
"""

import re
import traceback
from typing import Any, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class SanitizationResult:
    """Result of sanitizing an error."""
    original_length: int
    sanitized_length: int
    redaction_count: int
    sanitized_text: str


class ErrorSanitizer:
    """
    Sanitizes error messages to remove sensitive information.

    Usage:
        sanitizer = ErrorSanitizer()
        safe_message = sanitizer.sanitize(exception)
        safe_str = sanitizer.safe_str(some_object)
    """

    # Patterns to redact with their replacements
    REDACTION_PATTERNS: List[Tuple[str, str]] = [
        # API Keys - various formats
        (r"moltbook_[a-z]{2}_[A-Za-z0-9]+", "[REDACTED_MOLTBOOK_KEY]"),
        (r"sk-[A-Za-z0-9\-_]{20,}", "[REDACTED_API_KEY]"),
        (r"sk-ant-[A-Za-z0-9\-_]+", "[REDACTED_ANTHROPIC_KEY]"),
        (r"sk-proj-[A-Za-z0-9\-_]+", "[REDACTED_OPENAI_KEY]"),
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),

        # Bearer tokens
        (r"Bearer\s+[A-Za-z0-9\-_\.]+", "Bearer [REDACTED_TOKEN]"),
        (r"Authorization:\s*[^\s\n]+", "Authorization: [REDACTED]"),

        # File paths - redact usernames
        (r"/Users/[^/\s]+/", "/[REDACTED_USER]/"),
        (r"/home/[^/\s]+/", "/[REDACTED_USER]/"),
        (r"C:\\\\Users\\\\[^\\\\]+\\\\", "C:\\\\[REDACTED_USER]\\\\"),

        # Environment variables that might contain secrets
        (r"(ANTHROPIC_API_KEY|OPENAI_API_KEY|MOLTBOOK_API_KEY|SECRET_KEY|API_SECRET|AWS_SECRET_ACCESS_KEY)\s*=\s*[^\s\n]+",
         r"\1=[REDACTED]"),

        # Connection strings
        (r"(mongodb|mysql|postgres|redis|amqp)://[^\s]+", r"\1://[REDACTED]"),

        # Passwords in JSON/YAML
        (r'"password"\s*:\s*"[^"]*"', '"password": "[REDACTED]"'),
        (r"'password'\s*:\s*'[^']*'", "'password': '[REDACTED]'"),
        (r"password:\s*[^\s\n]+", "password: [REDACTED]"),

        # Generic secret patterns
        (r'"secret"\s*:\s*"[^"]*"', '"secret": "[REDACTED]"'),
        (r'"api_key"\s*:\s*"[^"]*"', '"api_key": "[REDACTED]"'),
        (r'"apiKey"\s*:\s*"[^"]*"', '"apiKey": "[REDACTED]"'),
        (r'"token"\s*:\s*"[^"]*"', '"token": "[REDACTED]"'),

        # Email addresses (potential PII)
        (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[REDACTED_EMAIL]"),

        # IP addresses (internal)
        (r"192\.168\.\d{1,3}\.\d{1,3}", "[REDACTED_IP]"),
        (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[REDACTED_IP]"),
        (r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}", "[REDACTED_IP]"),

        # Webhook URLs (might contain tokens)
        (r"https://hooks\.slack\.com/[^\s]+", "https://hooks.slack.com/[REDACTED]"),
        (r"https://discord\.com/api/webhooks/[^\s]+", "https://discord.com/api/webhooks/[REDACTED]"),
    ]

    def __init__(self, additional_patterns: Optional[List[Tuple[str, str]]] = None):
        """
        Initialize the error sanitizer.

        Args:
            additional_patterns: Extra (pattern, replacement) tuples to use
        """
        self.patterns = list(self.REDACTION_PATTERNS)
        if additional_patterns:
            self.patterns.extend(additional_patterns)

        # Pre-compile patterns
        self._compiled = [
            (re.compile(pattern, re.IGNORECASE | re.MULTILINE), replacement)
            for pattern, replacement in self.patterns
        ]

    def sanitize(self, error: Exception) -> str:
        """
        Sanitize an exception's message.

        Args:
            error: The exception to sanitize

        Returns:
            Sanitized error message string
        """
        # Get the error message
        message = str(error)

        # Also sanitize the traceback if available
        try:
            tb = traceback.format_exception(type(error), error, error.__traceback__)
            full_message = message + "\n" + "".join(tb)
        except Exception:
            full_message = message

        return self._sanitize_text(full_message)

    def sanitize_message(self, message: str) -> str:
        """
        Sanitize a plain text message.

        Args:
            message: The text to sanitize

        Returns:
            Sanitized text
        """
        return self._sanitize_text(message)

    def safe_str(self, obj: Any) -> str:
        """
        Convert any object to a sanitized string representation.

        Args:
            obj: Any object to convert

        Returns:
            Sanitized string representation
        """
        try:
            text = str(obj)
        except Exception:
            text = repr(obj)

        return self._sanitize_text(text)

    def sanitize_dict(self, data: dict) -> dict:
        """
        Recursively sanitize all string values in a dictionary.

        Args:
            data: Dictionary to sanitize

        Returns:
            New dictionary with sanitized values
        """
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                result[key] = self._sanitize_text(value)
            elif isinstance(value, dict):
                result[key] = self.sanitize_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self._sanitize_text(v) if isinstance(v, str)
                    else self.sanitize_dict(v) if isinstance(v, dict)
                    else v
                    for v in value
                ]
            else:
                result[key] = value
        return result

    def _sanitize_text(self, text: str) -> str:
        """Apply all redaction patterns to text."""
        if not text:
            return text

        result = text
        for pattern, replacement in self._compiled:
            result = pattern.sub(replacement, result)

        return result

    def get_sanitization_stats(self, text: str) -> SanitizationResult:
        """
        Get statistics about sanitization of text.

        Args:
            text: Text to analyze

        Returns:
            SanitizationResult with stats
        """
        sanitized = self._sanitize_text(text)

        # Count redactions
        redaction_count = sanitized.count("[REDACTED")

        return SanitizationResult(
            original_length=len(text),
            sanitized_length=len(sanitized),
            redaction_count=redaction_count,
            sanitized_text=sanitized
        )


# Global sanitizer instance
_sanitizer: Optional[ErrorSanitizer] = None


def get_sanitizer() -> ErrorSanitizer:
    """Get or create the global error sanitizer."""
    global _sanitizer
    if _sanitizer is None:
        _sanitizer = ErrorSanitizer()
    return _sanitizer


def sanitize_error(error: Exception) -> str:
    """
    Sanitize an exception's error message.

    Args:
        error: The exception to sanitize

    Returns:
        Sanitized error message
    """
    return get_sanitizer().sanitize(error)


def sanitize_message(message: str) -> str:
    """
    Sanitize a plain text message.

    Args:
        message: Text to sanitize

    Returns:
        Sanitized text
    """
    return get_sanitizer().sanitize_message(message)


def safe_str(obj: Any) -> str:
    """
    Convert any object to a sanitized string.

    Args:
        obj: Object to convert

    Returns:
        Sanitized string representation
    """
    return get_sanitizer().safe_str(obj)
