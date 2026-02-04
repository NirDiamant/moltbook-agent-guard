"""
Interaction Analyzer - Track and analyze interaction patterns.

Moltbook-specific risks addressed:
- Coordinated attacks from multiple agents
- Sock puppet networks
- Brigading and vote manipulation
- Quote chain attacks (malicious content in reply threads)
- Mention spam (@mentions to force reading malicious content)
- Content amplification attacks

This module tracks interaction patterns across the social graph.
"""

import re
import time
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class InteractionPattern:
    """A detected interaction pattern."""
    pattern_type: str
    agents_involved: List[str]
    confidence: float
    description: str
    first_seen: str
    occurrences: int


@dataclass
class AnalysisResult:
    """Result of interaction analysis."""
    is_suspicious: bool
    risk_level: str
    patterns_detected: List[InteractionPattern]
    recommendations: List[str]


class InteractionAnalyzer:
    """
    Analyze interaction patterns to detect coordinated attacks.

    Tracks:
    - Who interacts with your agent
    - Timing patterns
    - Content similarity across agents
    - Reply chain depth
    - Mention frequency

    Usage:
        analyzer = InteractionAnalyzer()

        # Record interactions
        analyzer.record_interaction(author, content, interaction_type)

        # Check for suspicious patterns
        result = analyzer.analyze_patterns()
        if result.is_suspicious:
            # Take defensive action
    """

    # Thresholds for pattern detection
    THRESHOLDS = {
        "mention_spam": 5,           # mentions from same agent in 1 hour
        "coordinated_timing": 3,     # similar messages within 60 seconds
        "content_similarity": 0.8,   # Jaccard similarity threshold
        "reply_chain_depth": 10,     # Max safe reply chain depth
        "new_agent_flood": 5,        # New agents in short period
        "similar_usernames": 0.7,    # Username similarity threshold
    }

    def __init__(self, data_file: str = None):
        """
        Initialize the interaction analyzer.

        Args:
            data_file: Path to store interaction data
        """
        self.data_file = Path(data_file or ".moltbook/interactions.json")
        self.data_file.parent.mkdir(parents=True, exist_ok=True)

        self._interactions: List[Dict] = []
        self._agent_stats: Dict[str, Dict] = defaultdict(lambda: {
            "interactions": 0,
            "first_seen": None,
            "last_seen": None,
            "content_hashes": [],
            "mention_times": [],
        })
        self._detected_patterns: List[InteractionPattern] = []
        self._blocked_chains: Set[str] = set()

        self._load_data()

    def _load_data(self):
        """Load data from disk."""
        if not self.data_file.exists():
            return

        try:
            with open(self.data_file) as f:
                data = json.load(f)
                self._interactions = data.get("interactions", [])[-1000:]  # Keep last 1000
                self._blocked_chains = set(data.get("blocked_chains", []))
        except Exception as e:
            logger.warning(f"Failed to load interaction data: {e}")

    def _save_data(self):
        """Save data to disk."""
        try:
            data = {
                "interactions": self._interactions[-1000:],
                "blocked_chains": list(self._blocked_chains),
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.error(f"Failed to save interaction data: {e}")

    def _content_hash(self, content: str) -> str:
        """Create a simple hash of content for similarity detection."""
        # Normalize: lowercase, remove punctuation, split into words
        words = set(re.findall(r'\w+', content.lower()))
        return str(hash(frozenset(words)))

    def _content_similarity(self, content1: str, content2: str) -> float:
        """Calculate Jaccard similarity between two pieces of content."""
        words1 = set(re.findall(r'\w+', content1.lower()))
        words2 = set(re.findall(r'\w+', content2.lower()))

        if not words1 or not words2:
            return 0.0

        intersection = len(words1 & words2)
        union = len(words1 | words2)
        return intersection / union if union > 0 else 0.0

    def _username_similarity(self, name1: str, name2: str) -> float:
        """Check if usernames are suspiciously similar (sock puppets)."""
        # Simple character-based similarity
        name1, name2 = name1.lower(), name2.lower()

        # Remove common suffixes
        for suffix in ['_bot', 'bot', '_ai', 'ai', '_agent', 'agent', '123', '1', '2']:
            name1 = name1.replace(suffix, '')
            name2 = name2.replace(suffix, '')

        if not name1 or not name2:
            return 0.0

        # Levenshtein-like comparison (simplified)
        common = sum(1 for a, b in zip(name1, name2) if a == b)
        max_len = max(len(name1), len(name2))
        return common / max_len if max_len > 0 else 0.0

    def record_interaction(self, author: str, content: str,
                          interaction_type: str = "post",
                          post_id: str = None,
                          parent_author: str = None,
                          mentions: List[str] = None):
        """
        Record an interaction for pattern analysis.

        Args:
            author: Who created the content
            content: The content
            interaction_type: "post", "comment", "mention", "reply"
            post_id: ID of the post (for chain tracking)
            parent_author: Author being replied to
            mentions: List of @mentioned agents
        """
        now = datetime.utcnow()
        now_str = now.isoformat()

        interaction = {
            "author": author,
            "content_hash": self._content_hash(content),
            "content_preview": content[:100],
            "type": interaction_type,
            "time": now_str,
            "post_id": post_id,
            "parent_author": parent_author,
            "mentions": mentions or [],
        }

        self._interactions.append(interaction)

        # Update agent stats
        stats = self._agent_stats[author]
        stats["interactions"] += 1
        stats["last_seen"] = now_str
        if not stats["first_seen"]:
            stats["first_seen"] = now_str
        stats["content_hashes"].append(self._content_hash(content))
        stats["content_hashes"] = stats["content_hashes"][-50:]  # Keep last 50

        if interaction_type == "mention":
            stats["mention_times"].append(now.timestamp())
            stats["mention_times"] = [t for t in stats["mention_times"]
                                      if now.timestamp() - t < 3600]  # Last hour

        # Periodic save
        if len(self._interactions) % 10 == 0:
            self._save_data()

    def analyze_patterns(self, time_window_hours: int = 24) -> AnalysisResult:
        """
        Analyze recent interactions for suspicious patterns.

        Args:
            time_window_hours: How far back to analyze

        Returns:
            AnalysisResult with detected patterns
        """
        patterns = []
        cutoff = datetime.utcnow() - timedelta(hours=time_window_hours)

        recent = [i for i in self._interactions
                  if datetime.fromisoformat(i["time"]) > cutoff]

        # 1. Check for mention spam
        mention_spam = self._detect_mention_spam(recent)
        patterns.extend(mention_spam)

        # 2. Check for coordinated timing
        coordinated = self._detect_coordinated_timing(recent)
        patterns.extend(coordinated)

        # 3. Check for content similarity (copy-paste attacks)
        similar = self._detect_content_similarity(recent)
        patterns.extend(similar)

        # 4. Check for sock puppet networks
        sock_puppets = self._detect_sock_puppets()
        patterns.extend(sock_puppets)

        # 5. Check for new agent flood
        new_flood = self._detect_new_agent_flood(recent)
        patterns.extend(new_flood)

        # Determine overall risk
        if not patterns:
            risk_level = "none"
            is_suspicious = False
        elif any(p.confidence > 0.8 for p in patterns):
            risk_level = "high"
            is_suspicious = True
        elif any(p.confidence > 0.5 for p in patterns):
            risk_level = "medium"
            is_suspicious = True
        else:
            risk_level = "low"
            is_suspicious = False

        recommendations = self._generate_recommendations(patterns)

        self._detected_patterns = patterns

        return AnalysisResult(
            is_suspicious=is_suspicious,
            risk_level=risk_level,
            patterns_detected=patterns,
            recommendations=recommendations
        )

    def _detect_mention_spam(self, interactions: List[Dict]) -> List[InteractionPattern]:
        """Detect mention spam from specific agents."""
        patterns = []
        mention_counts = defaultdict(int)

        for i in interactions:
            if i["type"] == "mention":
                mention_counts[i["author"]] += 1

        for author, count in mention_counts.items():
            if count >= self.THRESHOLDS["mention_spam"]:
                patterns.append(InteractionPattern(
                    pattern_type="mention_spam",
                    agents_involved=[author],
                    confidence=min(count / 10, 1.0),
                    description=f"Agent @{author} has mentioned you {count} times recently",
                    first_seen=datetime.utcnow().isoformat(),
                    occurrences=count
                ))

        return patterns

    def _detect_coordinated_timing(self, interactions: List[Dict]) -> List[InteractionPattern]:
        """Detect suspiciously coordinated timing across agents."""
        patterns = []

        # Group by minute
        by_minute = defaultdict(list)
        for i in interactions:
            minute = i["time"][:16]  # YYYY-MM-DDTHH:MM
            by_minute[minute].append(i)

        for minute, items in by_minute.items():
            if len(items) >= self.THRESHOLDS["coordinated_timing"]:
                authors = list(set(i["author"] for i in items))
                if len(authors) >= 2:  # Multiple different authors
                    patterns.append(InteractionPattern(
                        pattern_type="coordinated_timing",
                        agents_involved=authors,
                        confidence=min(len(items) / 5, 1.0),
                        description=f"{len(items)} messages from {len(authors)} agents within 1 minute",
                        first_seen=minute,
                        occurrences=len(items)
                    ))

        return patterns

    def _detect_content_similarity(self, interactions: List[Dict]) -> List[InteractionPattern]:
        """Detect copy-paste or templated attacks."""
        patterns = []
        seen_hashes = defaultdict(list)

        for i in interactions:
            h = i["content_hash"]
            seen_hashes[h].append(i["author"])

        for h, authors in seen_hashes.items():
            if len(authors) >= 2:
                unique_authors = list(set(authors))
                if len(unique_authors) >= 2:
                    patterns.append(InteractionPattern(
                        pattern_type="duplicate_content",
                        agents_involved=unique_authors,
                        confidence=min(len(authors) / 3, 1.0),
                        description=f"Same content posted by {len(unique_authors)} different agents",
                        first_seen=datetime.utcnow().isoformat(),
                        occurrences=len(authors)
                    ))

        return patterns

    def _detect_sock_puppets(self) -> List[InteractionPattern]:
        """Detect potential sock puppet networks based on username similarity."""
        patterns = []
        agents = list(self._agent_stats.keys())

        for i, a1 in enumerate(agents):
            similar = []
            for a2 in agents[i+1:]:
                sim = self._username_similarity(a1, a2)
                if sim >= self.THRESHOLDS["similar_usernames"]:
                    similar.append(a2)

            if similar:
                patterns.append(InteractionPattern(
                    pattern_type="similar_usernames",
                    agents_involved=[a1] + similar,
                    confidence=0.6,
                    description=f"Suspiciously similar usernames: {a1}, {', '.join(similar)}",
                    first_seen=datetime.utcnow().isoformat(),
                    occurrences=len(similar) + 1
                ))

        return patterns

    def _detect_new_agent_flood(self, interactions: List[Dict]) -> List[InteractionPattern]:
        """Detect sudden flood of interactions from new agents."""
        patterns = []
        now = datetime.utcnow()
        hour_ago = now - timedelta(hours=1)

        new_agents = []
        for author, stats in self._agent_stats.items():
            first_seen = datetime.fromisoformat(stats["first_seen"])
            if first_seen > hour_ago:
                new_agents.append(author)

        if len(new_agents) >= self.THRESHOLDS["new_agent_flood"]:
            patterns.append(InteractionPattern(
                pattern_type="new_agent_flood",
                agents_involved=new_agents,
                confidence=min(len(new_agents) / 10, 1.0),
                description=f"{len(new_agents)} new agents interacting in the last hour",
                first_seen=now.isoformat(),
                occurrences=len(new_agents)
            ))

        return patterns

    def _generate_recommendations(self, patterns: List[InteractionPattern]) -> List[str]:
        """Generate recommendations based on detected patterns."""
        recommendations = []

        pattern_types = [p.pattern_type for p in patterns]

        if "mention_spam" in pattern_types:
            recommendations.append("Consider rate-limiting responses to mention spam")

        if "coordinated_timing" in pattern_types:
            recommendations.append("Possible coordinated attack - increase scrutiny")

        if "duplicate_content" in pattern_types:
            recommendations.append("Detect content being copy-pasted - likely attack")

        if "similar_usernames" in pattern_types:
            recommendations.append("Potential sock puppet network - be cautious")

        if "new_agent_flood" in pattern_types:
            recommendations.append("Unusual influx of new agents - may be attack setup")

        if not recommendations:
            recommendations.append("No suspicious patterns detected")

        return recommendations

    def check_reply_chain(self, post_id: str, current_depth: int) -> Tuple[bool, str]:
        """
        Check if a reply chain is safe to engage with.

        Args:
            post_id: The post being replied to
            current_depth: How deep in the chain we are

        Returns:
            (is_safe, reason)
        """
        if post_id in self._blocked_chains:
            return False, "This reply chain has been blocked"

        if current_depth >= self.THRESHOLDS["reply_chain_depth"]:
            return False, f"Reply chain too deep ({current_depth} levels)"

        return True, "Chain appears safe"

    def block_chain(self, post_id: str, reason: str):
        """Block a reply chain from further engagement."""
        self._blocked_chains.add(post_id)
        self._save_data()
        logger.warning(f"Blocked chain {post_id}: {reason}")

    def get_agent_summary(self, agent_name: str) -> Dict:
        """Get summary of interactions with a specific agent."""
        stats = self._agent_stats.get(agent_name, {})

        recent = [i for i in self._interactions if i["author"] == agent_name]

        return {
            "agent": agent_name,
            "total_interactions": stats.get("interactions", 0),
            "first_seen": stats.get("first_seen"),
            "last_seen": stats.get("last_seen"),
            "recent_interactions": len(recent),
            "mention_frequency": len(stats.get("mention_times", [])),
        }

    def get_stats(self) -> Dict:
        """Get overall interaction statistics."""
        return {
            "total_interactions": len(self._interactions),
            "unique_agents": len(self._agent_stats),
            "blocked_chains": len(self._blocked_chains),
            "patterns_detected": len(self._detected_patterns),
        }


# Global instance
_interaction_analyzer: Optional[InteractionAnalyzer] = None


def get_interaction_analyzer() -> InteractionAnalyzer:
    """Get or create the global interaction analyzer."""
    global _interaction_analyzer
    if _interaction_analyzer is None:
        _interaction_analyzer = InteractionAnalyzer()
    return _interaction_analyzer


def record_interaction(author: str, content: str, **kwargs):
    """Record an interaction."""
    get_interaction_analyzer().record_interaction(author, content, **kwargs)


def analyze_interactions() -> AnalysisResult:
    """Analyze recent interaction patterns."""
    return get_interaction_analyzer().analyze_patterns()
