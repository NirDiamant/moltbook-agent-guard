"""
Audit Trail - Security event logging with integrity verification.

Provides append-only, hash-chained logging for security events.
Each entry is linked to the previous via cryptographic hash,
making it tamper-evident.

Events logged:
- attacks_blocked: Injection attempts detected and blocked
- key_rotation: API key changes
- config_changes: Security configuration changes
- errors: Security-related errors
- access: Sensitive resource access
- rate_limit: Rate limit events

This is FREE - uses only standard library hashlib.
"""

import os
import json
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from threading import Lock
import logging

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """A single audit log entry."""
    id: int
    timestamp: str
    event_type: str
    severity: str  # "info", "warning", "critical"
    details: Dict[str, Any]
    previous_hash: str
    entry_hash: str


class AuditTrail:
    """
    Append-only audit log with cryptographic integrity.

    Usage:
        audit = AuditTrail()
        audit.log("attack_blocked", {"type": "injection", "content": "..."}, "warning")

        # Verify log integrity
        is_valid, error = audit.verify_integrity()
        if not is_valid:
            print(f"Log tampering detected: {error}")
    """

    # Valid event types
    EVENT_TYPES = {
        "attack_blocked": "Injection or attack attempt blocked",
        "key_rotation": "API key was rotated",
        "config_change": "Security configuration changed",
        "error": "Security-related error occurred",
        "access": "Sensitive resource accessed",
        "rate_limit": "Rate limit triggered",
        "startup": "Agent started",
        "shutdown": "Agent stopped",
        "auth_failure": "Authentication failure",
        "output_blocked": "Output blocked by scanner",
        "memory_alert": "Suspicious memory pattern detected",
        "egress_blocked": "Outbound connection blocked",
        "skill_blocked": "Skill execution blocked",
        "credential_alert": "Credential access pattern detected",
    }

    # Severity levels
    SEVERITIES = ["info", "warning", "critical"]

    def __init__(self, log_file: str = None, max_entries: int = 10000):
        """
        Initialize the audit trail.

        Args:
            log_file: Path to audit log file
            max_entries: Maximum entries before rotation
        """
        self.log_file = Path(log_file or ".moltbook/audit.log")
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.max_entries = max_entries
        self._lock = Lock()
        self._entry_count = 0
        self._last_hash = "GENESIS"

        # Load existing log to get last hash
        self._initialize()

    def _initialize(self):
        """Initialize from existing log file."""
        if not self.log_file.exists():
            return

        try:
            with open(self.log_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        self._last_hash = entry.get("entry_hash", self._last_hash)
                        self._entry_count += 1
        except Exception as e:
            logger.warning(f"Failed to read audit log: {e}")

    def _compute_hash(self, entry_data: Dict) -> str:
        """Compute SHA-256 hash of entry data."""
        # Create deterministic string representation
        data_str = json.dumps(entry_data, sort_keys=True)
        return hashlib.sha256(data_str.encode()).hexdigest()[:16]

    def log(self, event_type: str, details: Dict[str, Any],
            severity: str = "info") -> AuditEntry:
        """
        Log a security event.

        Args:
            event_type: Type of event (see EVENT_TYPES)
            details: Event details dictionary
            severity: "info", "warning", or "critical"

        Returns:
            The created AuditEntry
        """
        if severity not in self.SEVERITIES:
            severity = "info"

        # Sanitize details to remove sensitive data
        safe_details = self._sanitize_details(details)

        with self._lock:
            self._entry_count += 1

            # Create entry data for hashing
            entry_data = {
                "id": self._entry_count,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": event_type,
                "severity": severity,
                "details": safe_details,
                "previous_hash": self._last_hash
            }

            # Compute hash
            entry_hash = self._compute_hash(entry_data)
            entry_data["entry_hash"] = entry_hash

            # Create entry object
            entry = AuditEntry(**entry_data)

            # Write to log
            self._write_entry(entry)

            # Update state
            self._last_hash = entry_hash

            # Check for rotation
            if self._entry_count >= self.max_entries:
                self._rotate_log()

            # Log critical events to standard logger too
            if severity == "critical":
                logger.critical(f"AUDIT: {event_type} - {safe_details}")

            return entry

    def _sanitize_details(self, details: Dict) -> Dict:
        """Remove sensitive information from details."""
        safe = {}
        sensitive_keys = ['password', 'secret', 'key', 'token', 'credential']

        for k, v in details.items():
            if any(s in k.lower() for s in sensitive_keys):
                safe[k] = "[REDACTED]"
            elif isinstance(v, str) and len(v) > 500:
                safe[k] = v[:500] + "...[truncated]"
            elif isinstance(v, dict):
                safe[k] = self._sanitize_details(v)
            else:
                safe[k] = v

        return safe

    def _write_entry(self, entry: AuditEntry):
        """Write entry to log file."""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(asdict(entry)) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit entry: {e}")

    def _rotate_log(self):
        """Rotate log file when it gets too large."""
        try:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            archive_path = self.log_file.with_suffix(f".{timestamp}.log")
            self.log_file.rename(archive_path)
            self._entry_count = 0
            logger.info(f"Rotated audit log to {archive_path}")
        except Exception as e:
            logger.error(f"Failed to rotate audit log: {e}")

    def verify_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Verify the integrity of the audit log.

        Checks that the hash chain is unbroken, indicating no tampering.

        Returns:
            (is_valid, error_message)
        """
        if not self.log_file.exists():
            return True, None

        try:
            previous_hash = "GENESIS"
            entry_count = 0

            with open(self.log_file) as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    entry = json.loads(line)
                    entry_count += 1

                    # Check previous hash links correctly
                    if entry.get("previous_hash") != previous_hash:
                        return False, f"Hash chain broken at entry {line_num}"

                    # Verify entry hash
                    stored_hash = entry.pop("entry_hash")
                    computed_hash = self._compute_hash(entry)

                    if stored_hash != computed_hash:
                        return False, f"Entry {line_num} has been modified"

                    previous_hash = stored_hash

            return True, None

        except json.JSONDecodeError as e:
            return False, f"Malformed JSON in audit log: {e}"
        except Exception as e:
            return False, f"Error verifying audit log: {e}"

    def query(self, event_type: str = None, severity: str = None,
              since: datetime = None, until: datetime = None,
              limit: int = 100) -> List[AuditEntry]:
        """
        Query the audit log.

        Args:
            event_type: Filter by event type
            severity: Filter by severity
            since: Filter by start time
            until: Filter by end time
            limit: Maximum entries to return

        Returns:
            List of matching AuditEntry objects
        """
        if not self.log_file.exists():
            return []

        results = []

        try:
            with open(self.log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    entry_data = json.loads(line)

                    # Apply filters
                    if event_type and entry_data.get("event_type") != event_type:
                        continue
                    if severity and entry_data.get("severity") != severity:
                        continue

                    if since or until:
                        entry_time = datetime.fromisoformat(
                            entry_data["timestamp"].rstrip("Z")
                        )
                        if since and entry_time < since:
                            continue
                        if until and entry_time > until:
                            continue

                    results.append(AuditEntry(**entry_data))

                    if len(results) >= limit:
                        break

        except Exception as e:
            logger.error(f"Error querying audit log: {e}")

        return results

    def get_stats(self) -> Dict:
        """
        Get statistics about the audit log.

        Returns:
            Statistics dictionary
        """
        if not self.log_file.exists():
            return {"total_entries": 0, "by_type": {}, "by_severity": {}}

        stats = {
            "total_entries": 0,
            "by_type": {},
            "by_severity": {},
            "integrity_verified": False
        }

        try:
            with open(self.log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    entry = json.loads(line)
                    stats["total_entries"] += 1

                    event_type = entry.get("event_type", "unknown")
                    stats["by_type"][event_type] = stats["by_type"].get(event_type, 0) + 1

                    severity = entry.get("severity", "info")
                    stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            # Verify integrity
            is_valid, _ = self.verify_integrity()
            stats["integrity_verified"] = is_valid

        except Exception as e:
            logger.error(f"Error getting audit stats: {e}")

        return stats

    def export(self, output_path: str, format: str = "json") -> bool:
        """
        Export audit log to a file.

        Args:
            output_path: Path to export file
            format: "json" or "csv"

        Returns:
            True if successful
        """
        entries = self.query(limit=self.max_entries)

        try:
            if format == "csv":
                import csv
                with open(output_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["id", "timestamp", "event_type", "severity",
                                   "details", "entry_hash"])
                    for entry in entries:
                        writer.writerow([
                            entry.id, entry.timestamp, entry.event_type,
                            entry.severity, json.dumps(entry.details),
                            entry.entry_hash
                        ])
            else:
                with open(output_path, 'w') as f:
                    json.dump([asdict(e) for e in entries], f, indent=2)

            return True

        except Exception as e:
            logger.error(f"Failed to export audit log: {e}")
            return False


# Global instance
_audit_trail: Optional[AuditTrail] = None


def get_audit_trail() -> AuditTrail:
    """Get or create the global audit trail."""
    global _audit_trail
    if _audit_trail is None:
        _audit_trail = AuditTrail()
    return _audit_trail


def audit_log(event_type: str, details: Dict[str, Any],
              severity: str = "info") -> AuditEntry:
    """
    Log a security event.

    Args:
        event_type: Type of event
        details: Event details
        severity: Event severity

    Returns:
        AuditEntry
    """
    return get_audit_trail().log(event_type, details, severity)


def verify_audit_integrity() -> Tuple[bool, Optional[str]]:
    """
    Verify audit log integrity.

    Returns:
        (is_valid, error_message)
    """
    return get_audit_trail().verify_integrity()
