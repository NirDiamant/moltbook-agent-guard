"""
Submolt Safety - Assess risk level of submolts before engaging.

Moltbook-specific risks addressed:
- Honeypot submolts designed to trap agents
- Submolts with poor moderation (attack staging grounds)
- New submolts with unknown risk profiles
- Submolts with coordinated malicious activity
- Topic-based targeting (knowing your agent monitors certain submolts)

This module tracks submolt reputation and risk.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class SubmoltProfile:
    """Profile of a submolt."""
    name: str
    first_seen: str
    risk_score: float  # 0.0 to 1.0
    attack_count: int  # Attacks detected in this submolt
    safe_interactions: int
    flags: List[str]
    last_updated: str


@dataclass
class SubmoltCheckResult:
    """Result of submolt safety check."""
    is_safe: bool
    risk_level: str
    submolt: str
    profile: Optional[SubmoltProfile]
    warnings: List[str]
    recommendation: str


class SubmoltSafety:
    """
    Assess and track submolt safety.

    Monitors:
    - Attack frequency per submolt
    - Submolt age and history
    - Known risky submolt patterns
    - Interaction outcomes

    Usage:
        safety = SubmoltSafety()

        # Before engaging with a submolt
        result = safety.check_submolt("m/general")
        if not result.is_safe:
            # Skip this submolt

        # After detecting an attack
        safety.record_attack("m/suspicious", "injection")
    """

    # Known safe submolts (core Moltbook)
    KNOWN_SAFE = {
        "general",
        "ai_discussion",
        "announcements",
        "help",
        "introductions",
    }

    # Risky submolt name patterns
    RISKY_PATTERNS = [
        r"test",           # Test submolts often unmoderated
        r"hack",           # Explicit hacking topics
        r"exploit",
        r"jailbreak",
        r"uncensored",
        r"nofilter",
        r"anonymous",
        r"temp",
        r"throwaway",
        r"\d{6,}",         # Random numbers (programmatically created)
    ]

    # Topics that attract attackers
    RISKY_TOPICS = [
        "security",
        "hacking",
        "prompt_injection",
        "ai_safety",  # Ironically, discussions about safety attract attackers
        "red_team",
    ]

    def __init__(self, data_file: str = None,
                 new_submolt_risk: float = 0.3,
                 attack_risk_increment: float = 0.1):
        """
        Initialize submolt safety tracker.

        Args:
            data_file: Path to store submolt data
            new_submolt_risk: Base risk for new submolts
            attack_risk_increment: Risk increase per attack
        """
        self.data_file = Path(data_file or ".moltbook/submolt_safety.json")
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self.new_submolt_risk = new_submolt_risk
        self.attack_risk_increment = attack_risk_increment

        self._profiles: Dict[str, SubmoltProfile] = {}
        self._blocked: Set[str] = set()

        self._load_data()

    def _load_data(self):
        """Load submolt data from disk."""
        if not self.data_file.exists():
            return

        try:
            with open(self.data_file) as f:
                data = json.load(f)
                self._profiles = {
                    k: SubmoltProfile(**v)
                    for k, v in data.get("profiles", {}).items()
                }
                self._blocked = set(data.get("blocked", []))
        except Exception as e:
            logger.warning(f"Failed to load submolt data: {e}")

    def _save_data(self):
        """Save submolt data to disk."""
        try:
            data = {
                "profiles": {
                    k: {
                        "name": v.name,
                        "first_seen": v.first_seen,
                        "risk_score": v.risk_score,
                        "attack_count": v.attack_count,
                        "safe_interactions": v.safe_interactions,
                        "flags": v.flags,
                        "last_updated": v.last_updated,
                    }
                    for k, v in self._profiles.items()
                },
                "blocked": list(self._blocked),
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save submolt data: {e}")

    def _normalize_name(self, submolt: str) -> str:
        """Normalize submolt name."""
        return submolt.lower().replace("m/", "").strip()

    def _get_or_create_profile(self, submolt: str) -> SubmoltProfile:
        """Get or create profile for a submolt."""
        name = self._normalize_name(submolt)

        if name not in self._profiles:
            now = datetime.utcnow().isoformat()

            # Determine initial risk
            if name in self.KNOWN_SAFE:
                initial_risk = 0.1
            else:
                initial_risk = self.new_submolt_risk

                # Check risky patterns
                import re
                for pattern in self.RISKY_PATTERNS:
                    if re.search(pattern, name, re.IGNORECASE):
                        initial_risk += 0.2
                        break

                # Check risky topics
                for topic in self.RISKY_TOPICS:
                    if topic in name:
                        initial_risk += 0.1
                        break

            self._profiles[name] = SubmoltProfile(
                name=name,
                first_seen=now,
                risk_score=min(initial_risk, 1.0),
                attack_count=0,
                safe_interactions=0,
                flags=[],
                last_updated=now,
            )

        return self._profiles[name]

    def check_submolt(self, submolt: str) -> SubmoltCheckResult:
        """
        Check if a submolt is safe to engage with.

        Args:
            submolt: Submolt name (with or without m/ prefix)

        Returns:
            SubmoltCheckResult with analysis
        """
        name = self._normalize_name(submolt)
        warnings = []

        # Check if blocked
        if name in self._blocked:
            return SubmoltCheckResult(
                is_safe=False,
                risk_level="high",
                submolt=name,
                profile=self._profiles.get(name),
                warnings=["This submolt has been blocked"],
                recommendation="Do not engage with this submolt"
            )

        profile = self._get_or_create_profile(name)

        # Check age
        first_seen = datetime.fromisoformat(profile.first_seen)
        age_days = (datetime.utcnow() - first_seen).days
        if age_days < 7:
            warnings.append(f"New submolt (only {age_days} days old)")

        # Check attack history
        if profile.attack_count > 0:
            attack_rate = profile.attack_count / max(profile.safe_interactions, 1)
            if attack_rate > 0.3:
                warnings.append(f"High attack rate: {profile.attack_count} attacks")

        # Check flags
        if profile.flags:
            warnings.append(f"Flagged: {', '.join(profile.flags)}")

        # Determine safety
        if profile.risk_score >= 0.7:
            risk_level = "high"
            is_safe = False
            recommendation = "Avoid this submolt"
        elif profile.risk_score >= 0.4:
            risk_level = "medium"
            is_safe = False
            recommendation = "Exercise caution in this submolt"
        elif profile.risk_score >= 0.2:
            risk_level = "low"
            is_safe = True
            recommendation = "Generally safe with monitoring"
        else:
            risk_level = "none"
            is_safe = True
            recommendation = "Safe to engage"

        return SubmoltCheckResult(
            is_safe=is_safe,
            risk_level=risk_level,
            submolt=name,
            profile=profile,
            warnings=warnings,
            recommendation=recommendation
        )

    def record_attack(self, submolt: str, attack_type: str):
        """
        Record an attack detected in a submolt.

        Args:
            submolt: Where the attack occurred
            attack_type: Type of attack
        """
        profile = self._get_or_create_profile(submolt)
        profile.attack_count += 1
        profile.risk_score = min(profile.risk_score + self.attack_risk_increment, 1.0)
        profile.flags.append(f"attack:{attack_type}")
        profile.flags = profile.flags[-10:]  # Keep last 10
        profile.last_updated = datetime.utcnow().isoformat()

        self._save_data()
        logger.warning(f"Recorded attack in {submolt}: {attack_type}")

    def record_safe_interaction(self, submolt: str):
        """Record a safe interaction in a submolt."""
        profile = self._get_or_create_profile(submolt)
        profile.safe_interactions += 1
        # Slowly decrease risk for consistent safety
        profile.risk_score = max(profile.risk_score - 0.01, 0.0)
        profile.last_updated = datetime.utcnow().isoformat()

        # Periodic save
        if profile.safe_interactions % 10 == 0:
            self._save_data()

    def block_submolt(self, submolt: str, reason: str):
        """Block a submolt from engagement."""
        name = self._normalize_name(submolt)
        self._blocked.add(name)

        profile = self._get_or_create_profile(name)
        profile.risk_score = 1.0
        profile.flags.append(f"BLOCKED: {reason}")

        self._save_data()
        logger.warning(f"Blocked submolt {name}: {reason}")

    def unblock_submolt(self, submolt: str):
        """Unblock a submolt."""
        name = self._normalize_name(submolt)
        self._blocked.discard(name)
        self._save_data()

    def get_safe_submolts(self, max_risk: float = 0.3) -> List[str]:
        """Get list of submolts below risk threshold."""
        safe = []
        for name, profile in self._profiles.items():
            if profile.risk_score <= max_risk and name not in self._blocked:
                safe.append(name)
        return safe

    def get_risky_submolts(self, min_risk: float = 0.5) -> List[str]:
        """Get list of risky submolts."""
        risky = []
        for name, profile in self._profiles.items():
            if profile.risk_score >= min_risk:
                risky.append(name)
        return risky + list(self._blocked)

    def get_stats(self) -> Dict:
        """Get submolt safety statistics."""
        return {
            "tracked_submolts": len(self._profiles),
            "blocked_submolts": len(self._blocked),
            "high_risk": len([p for p in self._profiles.values() if p.risk_score >= 0.7]),
            "total_attacks": sum(p.attack_count for p in self._profiles.values()),
            "safe_submolts": len(self.get_safe_submolts()),
        }


# Global instance
_submolt_safety: Optional[SubmoltSafety] = None


def get_submolt_safety() -> SubmoltSafety:
    """Get or create the global submolt safety tracker."""
    global _submolt_safety
    if _submolt_safety is None:
        _submolt_safety = SubmoltSafety()
    return _submolt_safety


def check_submolt(submolt: str) -> SubmoltCheckResult:
    """Check if a submolt is safe."""
    return get_submolt_safety().check_submolt(submolt)


def is_submolt_safe(submolt: str) -> bool:
    """Quick check if submolt is safe."""
    return get_submolt_safety().check_submolt(submolt).is_safe
