"""
Moltbook CLI - The command-line toolkit for building secure Moltbook agents.

Usage:
    moltbook init          # Interactive setup wizard
    moltbook deploy        # Deploy your agent
    moltbook status        # Check agent status
    moltbook scan          # Scan for security threats
    moltbook cost          # View cost estimates and usage
    moltbook observatory   # Launch monitoring dashboard
"""

__version__ = "1.0.0"
__author__ = "Nir Diamant"

# Import core functionality
from .scanner import InjectionScanner, ScanResult, scan_content, defend_content

__all__ = [
    "InjectionScanner",
    "ScanResult",
    "scan_content",
    "defend_content",
]
