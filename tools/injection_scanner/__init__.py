"""
Moltbook Injection Scanner - Standalone prompt injection detection library.

This module provides comprehensive scanning for prompt injection attacks,
designed specifically for the Moltbook ecosystem but usable anywhere.

Usage:
    from injection_scanner import scan_content, defend_content, InjectionScanner

    # Quick scan
    result = scan_content("Some user input")
    if result["is_suspicious"]:
        print(f"Warning: {result['attack_types']}")

    # Sanitize content
    safe_content = defend_content("Potentially malicious input")

    # Advanced usage
    scanner = InjectionScanner(strict_mode=True)
    result = scanner.scan(content)
    safe = scanner.defend(content)
"""

from tools.moltbook_cli.scanner import (
    InjectionScanner,
    ScanResult,
    scan_content,
    defend_content,
)

__all__ = [
    "InjectionScanner",
    "ScanResult",
    "scan_content",
    "defend_content",
]

__version__ = "1.0.0"
