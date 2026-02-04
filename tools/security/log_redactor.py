"""
Log Redactor - Automatic log sanitization.

Custom logging formatter that redacts sensitive patterns before output.
This ensures that even accidentally logged secrets don't appear in log files.

Usage:
    from tools.security.log_redactor import SecureLogger
    SecureLogger.configure(level="INFO")
    # All subsequent logging will be automatically redacted
"""

import re
import logging
from typing import List, Tuple, Optional


class RedactingFormatter(logging.Formatter):
    """
    A logging formatter that redacts sensitive patterns from log messages.

    Automatically removes:
    - API keys (Moltbook, OpenAI, Anthropic, AWS)
    - Bearer tokens
    - File paths with usernames
    - Passwords and secrets
    - Connection strings
    - Internal IP addresses
    """

    # Patterns to redact - same as ErrorSanitizer for consistency
    REDACTION_PATTERNS: List[Tuple[str, str]] = [
        # API Keys
        (r"moltbook_[a-z]{2}_[A-Za-z0-9]+", "[REDACTED_KEY]"),
        (r"sk-[A-Za-z0-9\-_]{20,}", "[REDACTED_KEY]"),
        (r"sk-ant-[A-Za-z0-9\-_]+", "[REDACTED_KEY]"),
        (r"sk-proj-[A-Za-z0-9\-_]+", "[REDACTED_KEY]"),
        (r"AKIA[0-9A-Z]{16}", "[REDACTED_KEY]"),

        # Tokens
        (r"Bearer\s+[A-Za-z0-9\-_\.]+", "Bearer [REDACTED]"),
        (r"token[=:]\s*[A-Za-z0-9\-_\.]+", "token=[REDACTED]"),

        # Paths
        (r"/Users/[^/\s]+/", "/[USER]/"),
        (r"/home/[^/\s]+/", "/[USER]/"),
        (r"C:\\Users\\[^\\]+\\", "C:\\\\[USER]\\\\"),

        # Passwords and secrets
        (r"password[=:]\s*[^\s]+", "password=[REDACTED]"),
        (r"secret[=:]\s*[^\s]+", "secret=[REDACTED]"),
        (r"api[_-]?key[=:]\s*[^\s]+", "api_key=[REDACTED]"),

        # Connection strings
        (r"(mongodb|mysql|postgres|redis)://[^\s]+", r"\1://[REDACTED]"),

        # Webhook URLs
        (r"https://hooks\.slack\.com/[^\s]+", "https://hooks.slack.com/[REDACTED]"),

        # Internal IPs
        (r"192\.168\.\d{1,3}\.\d{1,3}", "[INTERNAL_IP]"),
        (r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[INTERNAL_IP]"),
    ]

    def __init__(self, fmt: str = None, datefmt: str = None,
                 style: str = '%', additional_patterns: List[Tuple[str, str]] = None):
        """
        Initialize the redacting formatter.

        Args:
            fmt: Log format string
            datefmt: Date format string
            style: Format style (%, {, or $)
            additional_patterns: Extra (pattern, replacement) tuples
        """
        super().__init__(fmt, datefmt, style)

        patterns = list(self.REDACTION_PATTERNS)
        if additional_patterns:
            patterns.extend(additional_patterns)

        # Pre-compile patterns for efficiency
        self._compiled = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in patterns
        ]

    def _redact(self, text: str) -> str:
        """Apply all redaction patterns to text."""
        if not text:
            return text

        result = text
        for pattern, replacement in self._compiled:
            result = pattern.sub(replacement, result)
        return result

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the log record with redaction.

        Args:
            record: The log record to format

        Returns:
            Formatted and redacted log string
        """
        # Redact the message
        record.msg = self._redact(str(record.msg))

        # Redact args if present
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact(str(v)) for k, v in record.args.items()}
            else:
                record.args = tuple(self._redact(str(arg)) for arg in record.args)

        # Redact exception info if present
        if record.exc_info and record.exc_info[1]:
            exc_text = str(record.exc_info[1])
            # We can't modify the exception, but we can redact the formatted output

        # Format the record
        formatted = super().format(record)

        # Final redaction pass on the complete formatted output
        return self._redact(formatted)


class SecureLogger:
    """
    Utility class to configure secure logging with automatic redaction.

    Usage:
        SecureLogger.configure(level="INFO")
        # or
        logger = SecureLogger.get_logger("my_module")
    """

    _configured = False
    _default_format = '%(asctime)s [%(levelname)s] %(message)s'
    _default_datefmt = '%Y-%m-%d %H:%M:%S'

    @classmethod
    def configure(cls, level: str = "INFO",
                  format_string: str = None,
                  date_format: str = None,
                  additional_patterns: List[Tuple[str, str]] = None,
                  log_file: str = None) -> None:
        """
        Configure the root logger with secure formatting.

        Args:
            level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            format_string: Custom format string
            date_format: Custom date format
            additional_patterns: Extra redaction patterns
            log_file: Optional file to log to (in addition to console)
        """
        if cls._configured:
            return

        # Get the root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, level.upper()))

        # Create secure formatter
        formatter = RedactingFormatter(
            fmt=format_string or cls._default_format,
            datefmt=date_format or cls._default_datefmt,
            additional_patterns=additional_patterns
        )

        # Configure console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        # Configure file handler if specified
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)

        cls._configured = True

    @classmethod
    def get_logger(cls, name: str, level: str = None) -> logging.Logger:
        """
        Get a logger with secure formatting.

        Args:
            name: Logger name (usually __name__)
            level: Optional level override

        Returns:
            Configured logger
        """
        # Ensure root logger is configured
        if not cls._configured:
            cls.configure()

        logger = logging.getLogger(name)
        if level:
            logger.setLevel(getattr(logging, level.upper()))

        return logger

    @classmethod
    def reset(cls) -> None:
        """Reset the configuration (mainly for testing)."""
        cls._configured = False
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)


def configure_secure_logging(level: str = "INFO", **kwargs) -> None:
    """
    Configure secure logging with automatic redaction.

    Args:
        level: Logging level
        **kwargs: Additional arguments passed to SecureLogger.configure()
    """
    SecureLogger.configure(level=level, **kwargs)


def get_secure_logger(name: str) -> logging.Logger:
    """
    Get a secure logger by name.

    Args:
        name: Logger name

    Returns:
        Configured logger with redaction
    """
    return SecureLogger.get_logger(name)
