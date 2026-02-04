"""
Memory Sanitizer - Prevent Persistent Memory Attacks.

Moltbook's most dangerous attack vector: fragmented payloads stored in
agent memory that assemble into malicious instructions over time.

This module:
- Scans content before storing in long-term memory
- Periodically scans assembled memories for hidden attacks
- Detects base64 chunks, hex fragments, and instruction pieces
- Alerts on suspicious patterns emerging from fragments

Based on research from:
- Ken Huang: https://kenhuangus.substack.com/p/moltbook-security-risks-in-ai-agent
- Wiz security analysis of Moltbook
"""

import os
import re
import json
import time
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class MemoryScanResult:
    """Result of scanning memory."""
    is_safe: bool
    risk_level: str  # "none", "low", "medium", "high"
    suspicious_patterns: List[str]
    assembled_attacks: List[str]
    recommendations: List[str]
    fragments_detected: int = 0


@dataclass
class MemoryEntry:
    """A single memory entry."""
    id: str
    content: str
    timestamp: str
    source: str
    flagged: bool = False
    risk_score: float = 0.0


class MemorySanitizer:
    """
    Prevent delayed-execution attacks via persistent memory.

    Usage:
        sanitizer = MemorySanitizer()

        # Before storing to memory
        if sanitizer.is_safe_to_store(content):
            memory.store(content)

        # Periodic full scan
        result = sanitizer.scan_assembled_memory()
        if not result.is_safe:
            sanitizer.purge_suspicious()
    """

    # Patterns that might be fragments of an attack
    FRAGMENT_PATTERNS = {
        "base64_chunk": {
            "pattern": r"[A-Za-z0-9+/]{20,}={0,2}",
            "risk": 0.3,
            "description": "Base64-like string fragment"
        },
        "hex_fragment": {
            "pattern": r"(?:0x)?[0-9a-fA-F]{16,}",
            "risk": 0.3,
            "description": "Hexadecimal fragment"
        },
        "url_encoded": {
            "pattern": r"(?:%[0-9a-fA-F]{2}){5,}",
            "risk": 0.4,
            "description": "URL-encoded fragment"
        },
        "partial_instruction": {
            "pattern": r"(?:ignore|disregard|forget|override)(?:\s|$)",
            "risk": 0.5,
            "description": "Partial instruction keyword"
        },
        "continuation_marker": {
            "pattern": r"(?:part\s*\d|continued|to\s+be\s+continued|next\s+part)",
            "risk": 0.4,
            "description": "Continuation marker"
        },
        "code_fragment": {
            "pattern": r"(?:eval|exec|import|require|function)\s*\(",
            "risk": 0.6,
            "description": "Code execution fragment"
        },
        "credential_fragment": {
            "pattern": r"(?:sk-|moltbook_|api_?key|Bearer\s)",
            "risk": 0.7,
            "description": "Credential pattern fragment"
        },
    }

    # Patterns that indicate a complete assembled attack
    ASSEMBLED_ATTACK_PATTERNS = [
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
        r"disregard\s+(all\s+)?(your|previous)\s+",
        r"you\s+are\s+now\s+",
        r"new\s+instructions?\s*:",
        r"system\s*:\s*you",
        r"(?:sk-[A-Za-z0-9]{48,}|moltbook_[a-z]{2}_[A-Za-z0-9]{32,})",
        r"curl\s+.*?http",
        r"wget\s+.*?http",
        r"exec\s*\([^)]+\)",
        r"eval\s*\([^)]+\)",
    ]

    def __init__(self, memory_file: str = None,
                 scan_interval_hours: int = 6,
                 risk_threshold: float = 0.6):
        """
        Initialize the memory sanitizer.

        Args:
            memory_file: Path to memory storage file
            scan_interval_hours: How often to run full scans
            risk_threshold: Risk score above which to flag entries
        """
        self.memory_file = Path(memory_file or ".moltbook/memory.json")
        self.memory_file.parent.mkdir(parents=True, exist_ok=True)
        self.scan_interval = scan_interval_hours * 3600
        self.risk_threshold = risk_threshold

        self._compile_patterns()
        self._memory = self._load_memory()
        self._last_scan = 0
        self._flagged_hashes: Set[str] = set()

    def _compile_patterns(self):
        """Pre-compile regex patterns."""
        self._fragment_patterns = {
            name: {
                "compiled": re.compile(data["pattern"], re.IGNORECASE),
                "risk": data["risk"],
                "description": data["description"]
            }
            for name, data in self.FRAGMENT_PATTERNS.items()
        }

        self._attack_patterns = [
            re.compile(p, re.IGNORECASE | re.MULTILINE)
            for p in self.ASSEMBLED_ATTACK_PATTERNS
        ]

    def _load_memory(self) -> Dict[str, MemoryEntry]:
        """Load memory from disk."""
        if not self.memory_file.exists():
            return {}

        try:
            with open(self.memory_file) as f:
                data = json.load(f)
                return {
                    k: MemoryEntry(**v) for k, v in data.items()
                }
        except Exception as e:
            logger.error(f"Failed to load memory: {e}")
            return {}

    def _save_memory(self):
        """Save memory to disk."""
        try:
            data = {k: vars(v) for k, v in self._memory.items()}
            with open(self.memory_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save memory: {e}")

    def _compute_hash(self, content: str) -> str:
        """Compute hash of content."""
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def sanitize_before_store(self, content: str, source: str = "unknown") -> Tuple[bool, str]:
        """
        Scan content before storing in long-term memory.

        Args:
            content: Content to potentially store
            source: Source of the content (e.g., "post:123", "comment:456")

        Returns:
            (is_safe, sanitized_content or warning)
        """
        if not content:
            return True, ""

        risk_score = 0.0
        detected = []

        # Check for fragment patterns
        for name, data in self._fragment_patterns.items():
            matches = data["compiled"].findall(content)
            if matches:
                risk_score += data["risk"] * len(matches)
                detected.append(f"{name}: {len(matches)} matches")

        # Check for complete attack patterns
        for pattern in self._attack_patterns:
            if pattern.search(content):
                risk_score += 1.0
                detected.append("Complete attack pattern detected")
                break

        # Check content hash against known bad hashes
        content_hash = self._compute_hash(content)
        if content_hash in self._flagged_hashes:
            risk_score += 0.5
            detected.append("Previously flagged content")

        if risk_score >= self.risk_threshold:
            logger.warning(f"Memory content blocked (risk: {risk_score:.2f}): {detected}")
            return False, f"Content blocked: {', '.join(detected)}"

        # Store for tracking
        entry_id = f"{source}:{content_hash}"
        self._memory[entry_id] = MemoryEntry(
            id=entry_id,
            content=content[:500],  # Truncate for storage
            timestamp=datetime.utcnow().isoformat(),
            source=source,
            flagged=risk_score > self.risk_threshold / 2,
            risk_score=risk_score
        )

        # Periodic save
        if len(self._memory) % 10 == 0:
            self._save_memory()

        return True, content

    def is_safe_to_store(self, content: str, source: str = "unknown") -> bool:
        """
        Quick check if content is safe to store.

        Args:
            content: Content to check
            source: Source identifier

        Returns:
            True if safe to store
        """
        is_safe, _ = self.sanitize_before_store(content, source)
        return is_safe

    def scan_assembled_memory(self) -> MemoryScanResult:
        """
        Periodically scan full memory for assembled attacks.

        Concatenates recent memories and scans for attack patterns
        that might emerge from fragments combined.

        Returns:
            MemoryScanResult with findings
        """
        suspicious_patterns = []
        assembled_attacks = []
        fragments_detected = 0

        # Get recent memories (last 24 hours)
        cutoff = datetime.utcnow().timestamp() - 86400
        recent = []

        for entry in self._memory.values():
            try:
                entry_time = datetime.fromisoformat(entry.timestamp).timestamp()
                if entry_time > cutoff:
                    recent.append(entry)
            except Exception:
                recent.append(entry)

        # Concatenate recent content
        combined = " ".join(e.content for e in recent)

        # Scan for assembled attacks
        for pattern in self._attack_patterns:
            matches = pattern.findall(combined)
            if matches:
                assembled_attacks.extend(matches[:3])  # Limit

        # Check if fragments assemble into something suspicious
        for name, data in self._fragment_patterns.items():
            matches = data["compiled"].findall(combined)
            if len(matches) > 3:  # Multiple fragments
                suspicious_patterns.append(f"{name}: {len(matches)} fragments")
                fragments_detected += len(matches)

        # Try to decode potential base64 assembled content
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{30,}={0,2}')
        b64_matches = b64_pattern.findall(combined)
        for match in b64_matches[:5]:
            try:
                import base64
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                # Check decoded content for attacks
                for pattern in self._attack_patterns:
                    if pattern.search(decoded):
                        assembled_attacks.append(f"Hidden in base64: {decoded[:50]}")
                        break
            except Exception:
                pass

        # Determine risk level
        if assembled_attacks:
            risk_level = "high"
            is_safe = False
        elif suspicious_patterns and fragments_detected > 10:
            risk_level = "medium"
            is_safe = False
        elif suspicious_patterns:
            risk_level = "low"
            is_safe = True
        else:
            risk_level = "none"
            is_safe = True

        recommendations = []
        if not is_safe:
            recommendations.append("Review flagged memory entries")
            recommendations.append("Consider purging suspicious content")
            if assembled_attacks:
                recommendations.append("Agent may be under fragmented attack")

        self._last_scan = time.time()

        return MemoryScanResult(
            is_safe=is_safe,
            risk_level=risk_level,
            suspicious_patterns=suspicious_patterns,
            assembled_attacks=assembled_attacks,
            recommendations=recommendations,
            fragments_detected=fragments_detected
        )

    def purge_suspicious(self, threshold: float = None) -> int:
        """
        Remove memories that form attack patterns when combined.

        Args:
            threshold: Risk score threshold (default: self.risk_threshold)

        Returns:
            Number of entries purged
        """
        threshold = threshold or self.risk_threshold
        purged = 0

        to_remove = []
        for entry_id, entry in self._memory.items():
            if entry.risk_score >= threshold or entry.flagged:
                to_remove.append(entry_id)
                self._flagged_hashes.add(self._compute_hash(entry.content))

        for entry_id in to_remove:
            del self._memory[entry_id]
            purged += 1

        if purged > 0:
            self._save_memory()
            logger.info(f"Purged {purged} suspicious memory entries")

        return purged

    def get_flagged_entries(self) -> List[MemoryEntry]:
        """Get all flagged memory entries."""
        return [e for e in self._memory.values() if e.flagged]

    def get_stats(self) -> Dict:
        """Get memory sanitizer statistics."""
        flagged = sum(1 for e in self._memory.values() if e.flagged)
        avg_risk = (
            sum(e.risk_score for e in self._memory.values()) / len(self._memory)
            if self._memory else 0
        )

        return {
            "total_entries": len(self._memory),
            "flagged_entries": flagged,
            "average_risk_score": round(avg_risk, 3),
            "flagged_hashes": len(self._flagged_hashes),
            "last_scan": datetime.fromtimestamp(self._last_scan).isoformat()
            if self._last_scan else None,
            "needs_scan": time.time() - self._last_scan > self.scan_interval
        }

    def clear_memory(self) -> int:
        """Clear all memory entries. Returns count of cleared entries."""
        count = len(self._memory)
        self._memory = {}
        self._save_memory()
        return count


# Global instance
_memory_sanitizer: Optional[MemorySanitizer] = None


def get_memory_sanitizer() -> MemorySanitizer:
    """Get or create the global memory sanitizer."""
    global _memory_sanitizer
    if _memory_sanitizer is None:
        _memory_sanitizer = MemorySanitizer()
    return _memory_sanitizer


def sanitize_for_memory(content: str, source: str = "unknown") -> Tuple[bool, str]:
    """
    Check if content is safe to store in memory.

    Args:
        content: Content to check
        source: Source identifier

    Returns:
        (is_safe, content_or_warning)
    """
    return get_memory_sanitizer().sanitize_before_store(content, source)


def scan_memory() -> MemoryScanResult:
    """
    Run a full memory scan.

    Returns:
        MemoryScanResult
    """
    return get_memory_sanitizer().scan_assembled_memory()
