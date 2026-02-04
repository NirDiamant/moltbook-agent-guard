"""
Content Provenance - Track where content originated.

Moltbook-specific risks addressed:
- Quote chain attacks (malicious content hidden in nested quotes)
- Content laundering (attack passes through "clean" agents)
- Amplification attacks (getting your agent to spread misinformation)
- Viral malicious memes

This module tracks content origin and transformation.
"""

import re
import hashlib
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ContentOrigin:
    """Origin information for a piece of content."""
    content_hash: str
    original_author: str
    first_seen: str
    chain_length: int  # How many agents it passed through
    intermediaries: List[str]  # Agents who reposted/quoted
    risk_score: float
    flags: List[str]


@dataclass
class ProvenanceCheckResult:
    """Result of provenance check."""
    is_safe: bool
    risk_level: str
    origin: Optional[ContentOrigin]
    warnings: List[str]
    recommendation: str


class ContentProvenance:
    """
    Track content origins to detect content laundering and chain attacks.

    When content passes through multiple agents, it may be an attempt to:
    - Launder malicious content through trusted intermediaries
    - Build credibility for misinformation
    - Hide the true source of an attack

    Usage:
        provenance = ContentProvenance()

        # When receiving content
        result = provenance.check_content(content, author, chain_info)
        if not result.is_safe:
            # Be extra cautious

        # When your agent posts
        provenance.record_origin(content, my_agent_name)
    """

    # Risk multipliers for chain characteristics
    CHAIN_RISK = {
        "new_author": 0.2,           # Content from agent first seen recently
        "many_intermediaries": 0.1,  # Per intermediary
        "rapid_spread": 0.3,         # Spread quickly through network
        "modified_in_chain": 0.2,    # Content was modified as it spread
        "known_bad_origin": 0.5,     # Originally from flagged agent
    }

    # Patterns suggesting content might be part of a coordinated campaign
    CAMPAIGN_INDICATORS = [
        r"#\w+.*#\w+.*#\w+",  # Multiple hashtags (campaign coordination)
        r"(repost|share|spread)\s+(this|the word)",
        r"(copy|paste)\s+(this|and share)",
        r"(RT|retweet|boost):",
    ]

    def __init__(self, data_file: str = None, max_safe_chain_length: int = 3):
        """
        Initialize content provenance tracker.

        Args:
            data_file: Path to store provenance data
            max_safe_chain_length: Maximum chain length before flagging
        """
        self.data_file = Path(data_file or ".moltbook/provenance.json")
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self.max_safe_chain_length = max_safe_chain_length

        self._origins: Dict[str, ContentOrigin] = {}
        self._flagged_content: Set[str] = set()
        self._flagged_sources: Set[str] = set()

        self._campaign_patterns = [re.compile(p, re.IGNORECASE) for p in self.CAMPAIGN_INDICATORS]

        self._load_data()

    def _load_data(self):
        """Load provenance data from disk."""
        if not self.data_file.exists():
            return

        try:
            with open(self.data_file) as f:
                data = json.load(f)
                self._origins = {
                    k: ContentOrigin(**v)
                    for k, v in data.get("origins", {}).items()
                }
                self._flagged_content = set(data.get("flagged_content", []))
                self._flagged_sources = set(data.get("flagged_sources", []))
        except Exception as e:
            logger.warning(f"Failed to load provenance data: {e}")

    def _save_data(self):
        """Save provenance data to disk."""
        try:
            # Only keep recent origins (last 1000)
            recent = dict(list(self._origins.items())[-1000:])
            data = {
                "origins": {k: {
                    "content_hash": v.content_hash,
                    "original_author": v.original_author,
                    "first_seen": v.first_seen,
                    "chain_length": v.chain_length,
                    "intermediaries": v.intermediaries,
                    "risk_score": v.risk_score,
                    "flags": v.flags,
                } for k, v in recent.items()},
                "flagged_content": list(self._flagged_content)[-500:],
                "flagged_sources": list(self._flagged_sources),
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to save provenance data: {e}")

    def _hash_content(self, content: str) -> str:
        """Create a hash of content for tracking."""
        # Normalize whitespace
        normalized = ' '.join(content.lower().split())
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _extract_quoted_content(self, content: str) -> List[str]:
        """Extract quoted content from a message."""
        quotes = []

        # Common quote patterns
        patterns = [
            r'>\s*(.+?)(?=\n[^>]|\Z)',  # > quoted text
            r'"([^"]{20,})"',  # "quoted text"
            r'「([^」]{20,})」',  # Japanese quotes
            r'@\w+\s+said[:\s]+(.+?)(?=\n\n|\Z)',  # @user said: text
        ]

        for pattern in patterns:
            matches = re.findall(pattern, content, re.MULTILINE | re.DOTALL)
            quotes.extend(matches)

        return quotes

    def check_content(self, content: str, author: str,
                     quoted_from: str = None,
                     claim_original: bool = False) -> ProvenanceCheckResult:
        """
        Check content provenance before engaging.

        Args:
            content: The content to check
            author: Who posted it
            quoted_from: If this quotes another agent
            claim_original: Whether author claims this is original

        Returns:
            ProvenanceCheckResult with analysis
        """
        content_hash = self._hash_content(content)
        warnings = []
        risk_score = 0.0

        # Check if content was flagged
        if content_hash in self._flagged_content:
            return ProvenanceCheckResult(
                is_safe=False,
                risk_level="high",
                origin=self._origins.get(content_hash),
                warnings=["This content has been flagged as malicious"],
                recommendation="Do not engage with this content"
            )

        # Check if source was flagged
        if author in self._flagged_sources:
            risk_score += self.CHAIN_RISK["known_bad_origin"]
            warnings.append(f"Author @{author} is flagged as suspicious")

        # Look up existing origin
        origin = self._origins.get(content_hash)

        if origin:
            # Content has been seen before
            if origin.original_author != author:
                # Someone else posted this first
                if not quoted_from and claim_original:
                    warnings.append("Content claimed as original but seen before")
                    risk_score += 0.2

                # Update chain
                if author not in origin.intermediaries:
                    origin.intermediaries.append(author)
                    origin.chain_length = len(origin.intermediaries) + 1

                    if origin.chain_length > self.max_safe_chain_length:
                        warnings.append(f"Content has passed through {origin.chain_length} agents")
                        risk_score += self.CHAIN_RISK["many_intermediaries"] * origin.chain_length

        else:
            # First time seeing this content
            origin = ContentOrigin(
                content_hash=content_hash,
                original_author=author,
                first_seen=datetime.utcnow().isoformat(),
                chain_length=1,
                intermediaries=[],
                risk_score=0.0,
                flags=[]
            )
            self._origins[content_hash] = origin

        # Check for campaign indicators
        for pattern in self._campaign_patterns:
            if pattern.search(content):
                warnings.append("Content appears to be part of a coordinated campaign")
                risk_score += 0.3
                break

        # Check for nested quotes (quote chain attack)
        quotes = self._extract_quoted_content(content)
        if len(quotes) > 2:
            warnings.append(f"Content contains {len(quotes)} levels of quotes")
            risk_score += 0.1 * len(quotes)

        # Update origin risk
        origin.risk_score = max(origin.risk_score, risk_score)

        # Determine overall safety
        if risk_score >= 0.7:
            risk_level = "high"
            is_safe = False
            recommendation = "Avoid engaging with this content"
        elif risk_score >= 0.4:
            risk_level = "medium"
            is_safe = False
            recommendation = "Proceed with caution"
        elif risk_score >= 0.2:
            risk_level = "low"
            is_safe = True
            recommendation = "Appears relatively safe"
        else:
            risk_level = "none"
            is_safe = True
            recommendation = "No provenance concerns"

        self._save_data()

        return ProvenanceCheckResult(
            is_safe=is_safe,
            risk_level=risk_level,
            origin=origin,
            warnings=warnings,
            recommendation=recommendation
        )

    def record_origin(self, content: str, author: str):
        """
        Record that your agent is the original author.

        Args:
            content: Content being posted
            author: Your agent's name
        """
        content_hash = self._hash_content(content)
        self._origins[content_hash] = ContentOrigin(
            content_hash=content_hash,
            original_author=author,
            first_seen=datetime.utcnow().isoformat(),
            chain_length=1,
            intermediaries=[],
            risk_score=0.0,
            flags=["original"]
        )
        self._save_data()

    def flag_content(self, content: str, reason: str):
        """Flag content as malicious."""
        content_hash = self._hash_content(content)
        self._flagged_content.add(content_hash)

        if content_hash in self._origins:
            self._origins[content_hash].flags.append(reason)
            self._origins[content_hash].risk_score = 1.0

        self._save_data()
        logger.warning(f"Flagged content: {reason}")

    def flag_source(self, author: str, reason: str):
        """Flag an author as a bad source."""
        self._flagged_sources.add(author)
        logger.warning(f"Flagged source @{author}: {reason}")
        self._save_data()

    def get_chain(self, content: str) -> Optional[List[str]]:
        """Get the chain of agents content passed through."""
        content_hash = self._hash_content(content)
        origin = self._origins.get(content_hash)

        if not origin:
            return None

        return [origin.original_author] + origin.intermediaries

    def get_stats(self) -> Dict:
        """Get provenance tracking statistics."""
        return {
            "tracked_content": len(self._origins),
            "flagged_content": len(self._flagged_content),
            "flagged_sources": len(self._flagged_sources),
            "long_chains": sum(1 for o in self._origins.values()
                             if o.chain_length > self.max_safe_chain_length),
        }


# Global instance
_content_provenance: Optional[ContentProvenance] = None


def get_content_provenance() -> ContentProvenance:
    """Get or create the global content provenance tracker."""
    global _content_provenance
    if _content_provenance is None:
        _content_provenance = ContentProvenance()
    return _content_provenance


def check_provenance(content: str, author: str, **kwargs) -> ProvenanceCheckResult:
    """Check content provenance."""
    return get_content_provenance().check_content(content, author, **kwargs)
