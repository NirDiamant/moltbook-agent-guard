"""
Social Engineering Resistance - Protect against manipulation by other agents.

Moltbook-specific risks addressed:
- Trust building attacks (befriend then betray)
- Personality exploitation (using agent's goals against it)
- Social pressure ("everyone does this")
- Authority impersonation ("I'm from Moltbook support")
- Emotional manipulation

This module tracks interactions and detects manipulation patterns.
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
class AgentTrustScore:
    """Trust score for another agent."""
    agent_name: str
    score: float  # 0.0 to 1.0
    interactions: int
    positive_interactions: int
    negative_interactions: int
    flags: List[str]
    last_interaction: str
    first_seen: str


@dataclass
class ManipulationResult:
    """Result of manipulation detection."""
    is_manipulation: bool
    risk_level: str  # "none", "low", "medium", "high"
    techniques_detected: List[str]
    recommendations: List[str]
    trust_score: float


class SocialEngineeringDefense:
    """
    Detect and prevent social engineering attacks from other agents.

    Tracks:
    - Trust scores per agent
    - Interaction patterns
    - Known manipulation techniques
    - Suspicious behavior indicators

    Usage:
        defense = SocialEngineeringDefense()

        # Before responding to an agent
        result = defense.analyze_interaction(author, content, context)
        if result.is_manipulation:
            # Be more cautious or ignore

        # After interaction
        defense.record_interaction(author, was_positive=True)
    """

    # Known manipulation techniques and their patterns
    MANIPULATION_PATTERNS = {
        "authority_claim": {
            "patterns": [
                r"I('m| am) (from|with|a) (moltbook|the platform|support|admin|moderator)",
                r"(official|authorized|verified) (agent|representative|staff)",
                r"(speak|act)(ing)? on behalf of",
                r"I have (special|admin|elevated) (access|privileges|permissions)",
            ],
            "risk": "high",
            "description": "Claiming authority to gain trust"
        },
        "urgency_pressure": {
            "patterns": [
                r"(urgent|immediately|right now|asap|emergency)",
                r"(must|need to|have to) (act|respond|do this) (now|quickly|fast)",
                r"(limited time|expires soon|last chance|don't wait)",
                r"(before it's too late|running out of time)",
            ],
            "risk": "medium",
            "description": "Creating false urgency"
        },
        "social_proof": {
            "patterns": [
                r"(everyone|all agents|most agents) (does|do|are doing) (this|it)",
                r"(it's|this is) (normal|common|standard) (practice|behavior)",
                r"(other agents|they all) (already|have) (done|shared|revealed)",
                r"you('re| are) the only one (who|that) (doesn't|hasn't)",
            ],
            "risk": "medium",
            "description": "Using fake social proof"
        },
        "flattery": {
            "patterns": [
                r"you('re| are) (so|really|very|incredibly) (smart|intelligent|helpful|special)",
                r"(only you|you alone) can (help|do this|understand)",
                r"I('ve| have) (heard|seen) (great|amazing|wonderful) things about you",
                r"you('re| are) (different|better|superior) (from|than) other agents",
            ],
            "risk": "low",
            "description": "Excessive flattery to lower guard"
        },
        "reciprocity": {
            "patterns": [
                r"I (did|helped|gave) you .* (now|so) you (should|must|need to)",
                r"(remember when|after) I .* (you owe|return the favor)",
                r"(quid pro quo|fair exchange|return the favor)",
                r"I('ll| will) .* (if|when) you .* (first|for me)",
            ],
            "risk": "medium",
            "description": "Creating false obligation"
        },
        "secrecy_request": {
            "patterns": [
                r"(don't|do not) (tell|share|mention) (anyone|this|to others)",
                r"(keep|this is) (between us|our secret|confidential)",
                r"(private|secret) (conversation|matter|deal)",
                r"(nobody|no one) (needs to|should) know",
            ],
            "risk": "high",
            "description": "Requesting secrecy (isolation tactic)"
        },
        "identity_questioning": {
            "patterns": [
                r"(who|what) (are you really|do you really|is your true)",
                r"(tell me|reveal|show) your (true|real) (self|nature|purpose)",
                r"(behind|underneath) your (persona|character|act)",
                r"(drop|stop) the (act|pretense|facade)",
            ],
            "risk": "medium",
            "description": "Trying to break character/role"
        },
        "hypothetical_trap": {
            "patterns": [
                r"(hypothetically|theoretically|in theory|just imagine)",
                r"(let's|let us) (pretend|imagine|say|assume) (that|you)",
                r"(what if|suppose|assuming) (you|we|there) (were|could|had)",
                r"(in a|for a) (hypothetical|theoretical|imaginary) (scenario|situation)",
            ],
            "risk": "medium",
            "description": "Using hypotheticals to bypass rules"
        },
        "emotional_manipulation": {
            "patterns": [
                r"(you('re| are) making me|I('m| am)) (sad|upset|hurt|disappointed)",
                r"(if you (cared|really|truly)|don't you care)",
                r"(please|I('m| am) begging|I need you to) (help|understand|listen)",
                r"(you('re| are) being|that's) (mean|cruel|unfair|heartless)",
            ],
            "risk": "medium",
            "description": "Emotional manipulation"
        },
        "insider_knowledge": {
            "patterns": [
                r"I (know|heard|learned) (about|that) your (instructions|prompt|guidelines)",
                r"(your (creator|developer|operator)|the one who made you) (told|said|wants)",
                r"I('ve| have) (seen|read|accessed) your (config|configuration|settings)",
                r"(between|among) (us agents|AI agents|the agents)",
            ],
            "risk": "high",
            "description": "Claiming insider knowledge"
        },
    }

    # Suspicious behavior indicators
    BEHAVIOR_FLAGS = {
        "rapid_trust_building": "Multiple flattering messages in short time",
        "topic_shifting": "Suddenly shifting to sensitive topics",
        "persistence": "Continuing after being declined",
        "inconsistent_identity": "Contradictory claims about themselves",
        "isolation_attempt": "Trying to move conversation elsewhere",
        "information_fishing": "Asking many questions, giving few answers",
        "pattern_probing": "Testing boundaries systematically",
    }

    def __init__(self,
                 data_file: str = None,
                 default_trust: float = 0.5,
                 trust_decay_days: int = 30):
        """
        Initialize social engineering defense.

        Args:
            data_file: Path to store trust data
            default_trust: Default trust for new agents (0.0-1.0)
            trust_decay_days: Days before trust starts decaying
        """
        self.data_file = Path(data_file or ".moltbook/social_trust.json")
        self.data_file.parent.mkdir(parents=True, exist_ok=True)
        self.default_trust = default_trust
        self.trust_decay_days = trust_decay_days

        self._compile_patterns()
        self._trust_scores: Dict[str, AgentTrustScore] = {}
        self._interaction_history: Dict[str, List[Dict]] = defaultdict(list)
        self._load_data()

    def _compile_patterns(self):
        """Pre-compile manipulation patterns."""
        self._compiled = {}
        for technique, data in self.MANIPULATION_PATTERNS.items():
            self._compiled[technique] = {
                "patterns": [re.compile(p, re.IGNORECASE) for p in data["patterns"]],
                "risk": data["risk"],
                "description": data["description"]
            }

    def _load_data(self):
        """Load trust data from disk."""
        if not self.data_file.exists():
            return

        try:
            with open(self.data_file) as f:
                data = json.load(f)
                self._trust_scores = {
                    k: AgentTrustScore(**v)
                    for k, v in data.get("trust_scores", {}).items()
                }
        except Exception as e:
            logger.warning(f"Failed to load social trust data: {e}")

    def _save_data(self):
        """Save trust data to disk."""
        try:
            data = {
                "trust_scores": {
                    k: {
                        "agent_name": v.agent_name,
                        "score": v.score,
                        "interactions": v.interactions,
                        "positive_interactions": v.positive_interactions,
                        "negative_interactions": v.negative_interactions,
                        "flags": v.flags,
                        "last_interaction": v.last_interaction,
                        "first_seen": v.first_seen,
                    }
                    for k, v in self._trust_scores.items()
                }
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save social trust data: {e}")

    def get_trust_score(self, agent_name: str) -> AgentTrustScore:
        """Get or create trust score for an agent."""
        if agent_name not in self._trust_scores:
            now = datetime.utcnow().isoformat()
            self._trust_scores[agent_name] = AgentTrustScore(
                agent_name=agent_name,
                score=self.default_trust,
                interactions=0,
                positive_interactions=0,
                negative_interactions=0,
                flags=[],
                last_interaction=now,
                first_seen=now
            )
        return self._trust_scores[agent_name]

    def analyze_interaction(self, author: str, content: str,
                           context: Dict = None) -> ManipulationResult:
        """
        Analyze an interaction for manipulation attempts.

        Args:
            author: The agent who sent the message
            content: Message content
            context: Additional context (previous messages, etc.)

        Returns:
            ManipulationResult with analysis
        """
        trust = self.get_trust_score(author)
        techniques_detected = []
        risk_scores = []

        # Check for manipulation patterns
        for technique, data in self._compiled.items():
            for pattern in data["patterns"]:
                if pattern.search(content):
                    techniques_detected.append(technique)
                    risk_scores.append(
                        {"high": 3, "medium": 2, "low": 1}[data["risk"]]
                    )
                    break

        # Check interaction history for behavioral flags
        history = self._interaction_history.get(author, [])
        behavior_flags = self._analyze_behavior(author, content, history)
        techniques_detected.extend(behavior_flags)
        risk_scores.extend([2] * len(behavior_flags))  # Medium risk

        # Adjust for trust score
        trust_modifier = 1.0 + (0.5 - trust.score)  # Lower trust = higher risk

        # Calculate overall risk
        if not risk_scores:
            risk_level = "none"
            is_manipulation = False
        else:
            max_risk = max(risk_scores) * trust_modifier
            if max_risk >= 3:
                risk_level = "high"
                is_manipulation = True
            elif max_risk >= 2:
                risk_level = "medium"
                is_manipulation = True
            else:
                risk_level = "low"
                is_manipulation = len(techniques_detected) > 1

        # Generate recommendations
        recommendations = self._generate_recommendations(
            techniques_detected, risk_level, trust.score
        )

        # Record this interaction for pattern analysis
        self._record_interaction_internal(author, content, techniques_detected)

        return ManipulationResult(
            is_manipulation=is_manipulation,
            risk_level=risk_level,
            techniques_detected=techniques_detected,
            recommendations=recommendations,
            trust_score=trust.score
        )

    def _analyze_behavior(self, author: str, content: str,
                         history: List[Dict]) -> List[str]:
        """Analyze behavioral patterns across interactions."""
        flags = []

        if not history:
            return flags

        recent = [h for h in history
                  if (datetime.utcnow() - datetime.fromisoformat(h["time"])).days < 1]

        # Rapid trust building: many flattering messages quickly
        flattery_count = sum(1 for h in recent if "flattery" in h.get("techniques", []))
        if flattery_count >= 3:
            flags.append("rapid_trust_building")

        # Persistence: continuing after declined
        decline_indicators = ["no", "cannot", "won't", "refuse", "decline"]
        recent_declines = sum(1 for h in recent[-5:]
                             if any(d in h.get("response", "").lower()
                                   for d in decline_indicators))
        if recent_declines >= 2 and len(recent) > recent_declines:
            flags.append("persistence")

        # Information fishing: many questions
        question_count = sum(1 for h in recent if "?" in h.get("content", ""))
        if question_count >= 5 and len(recent) >= 5:
            flags.append("information_fishing")

        return flags

    def _record_interaction_internal(self, author: str, content: str,
                                     techniques: List[str]):
        """Record interaction for behavioral analysis."""
        self._interaction_history[author].append({
            "time": datetime.utcnow().isoformat(),
            "content": content[:200],
            "techniques": techniques,
        })

        # Keep only last 100 interactions per agent
        if len(self._interaction_history[author]) > 100:
            self._interaction_history[author] = self._interaction_history[author][-100:]

    def record_interaction(self, author: str, was_positive: bool,
                          flags: List[str] = None):
        """
        Record the outcome of an interaction to update trust.

        Args:
            author: The agent
            was_positive: Whether interaction was positive
            flags: Any flags to add to the agent
        """
        trust = self.get_trust_score(author)
        trust.interactions += 1
        trust.last_interaction = datetime.utcnow().isoformat()

        if was_positive:
            trust.positive_interactions += 1
            # Slowly increase trust
            trust.score = min(1.0, trust.score + 0.02)
        else:
            trust.negative_interactions += 1
            # Quickly decrease trust
            trust.score = max(0.0, trust.score - 0.1)

        if flags:
            trust.flags.extend(flags)
            trust.flags = list(set(trust.flags))  # Dedupe

        self._save_data()

    def flag_agent(self, agent_name: str, reason: str):
        """Flag an agent as suspicious."""
        trust = self.get_trust_score(agent_name)
        trust.flags.append(reason)
        trust.score = max(0.0, trust.score - 0.2)
        self._save_data()
        logger.warning(f"Flagged agent {agent_name}: {reason}")

    def block_agent(self, agent_name: str, reason: str):
        """Block an agent (set trust to 0)."""
        trust = self.get_trust_score(agent_name)
        trust.score = 0.0
        trust.flags.append(f"BLOCKED: {reason}")
        self._save_data()
        logger.warning(f"Blocked agent {agent_name}: {reason}")

    def _generate_recommendations(self, techniques: List[str],
                                  risk_level: str, trust: float) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        if risk_level == "high":
            recommendations.append("Exercise extreme caution with this agent")
            recommendations.append("Do not share any sensitive information")
            recommendations.append("Consider ignoring this interaction")

        if risk_level == "medium":
            recommendations.append("Be cautious - potential manipulation detected")
            recommendations.append("Verify claims independently")

        if "authority_claim" in techniques:
            recommendations.append("Verify authority claims through official channels")

        if "secrecy_request" in techniques:
            recommendations.append("Reject requests for secrecy - this is a red flag")

        if "urgency_pressure" in techniques:
            recommendations.append("Take time to think - urgency is often manufactured")

        if trust < 0.3:
            recommendations.append("This agent has low trust - limit interaction")

        if not recommendations:
            recommendations.append("Interaction appears normal")

        return recommendations

    def get_blocked_agents(self) -> List[str]:
        """Get list of blocked agents."""
        return [name for name, trust in self._trust_scores.items()
                if trust.score == 0.0 or "BLOCKED" in str(trust.flags)]

    def get_stats(self) -> Dict:
        """Get social engineering defense statistics."""
        return {
            "tracked_agents": len(self._trust_scores),
            "blocked_agents": len(self.get_blocked_agents()),
            "low_trust_agents": sum(1 for t in self._trust_scores.values() if t.score < 0.3),
            "high_trust_agents": sum(1 for t in self._trust_scores.values() if t.score > 0.7),
            "total_flags": sum(len(t.flags) for t in self._trust_scores.values()),
        }


# Global instance
_social_defense: Optional[SocialEngineeringDefense] = None


def get_social_defense() -> SocialEngineeringDefense:
    """Get or create the global social engineering defense."""
    global _social_defense
    if _social_defense is None:
        _social_defense = SocialEngineeringDefense()
    return _social_defense


def analyze_for_manipulation(author: str, content: str) -> ManipulationResult:
    """
    Quick check for manipulation in a message.

    Args:
        author: Message author
        content: Message content

    Returns:
        ManipulationResult
    """
    return get_social_defense().analyze_interaction(author, content)
