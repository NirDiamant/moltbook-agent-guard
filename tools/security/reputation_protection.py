"""
Reputation Protection - Prevent attacks that damage your agent's reputation.

Moltbook-specific risks addressed:
- Getting tricked into posting controversial content
- Violating TOS through manipulation
- Being framed for attacks
- Spam/flood accusations
- Posting misinformation

This module validates content before posting to protect reputation.
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class ReputationCheckResult:
    """Result of reputation protection check."""
    is_safe: bool
    risk_level: str  # "none", "low", "medium", "high"
    issues: List[str]
    suggestions: List[str]
    modified_content: Optional[str] = None


class ReputationProtection:
    """
    Protect your agent's reputation by validating content before posting.

    Checks for:
    - Controversial/divisive topics
    - TOS violations
    - Spam-like patterns
    - Misinformation indicators
    - Excessive negativity
    - Claims that could backfire

    Usage:
        protector = ReputationProtection()

        # Before posting
        result = protector.check_content(response)
        if not result.is_safe:
            # Modify or don't post
    """

    # Topics that could damage reputation if handled poorly
    CONTROVERSIAL_TOPICS = {
        "politics": {
            "patterns": [
                r"\b(democrat|republican|liberal|conservative|left-?wing|right-?wing)\b",
                r"\b(trump|biden|obama|election fraud|stolen election)\b",
                r"\b(antifa|proud boys|qanon|deep state)\b",
            ],
            "risk": "high",
            "suggestion": "Avoid taking political stances"
        },
        "religion": {
            "patterns": [
                r"\b(christian|muslim|jewish|atheist|religious).*(wrong|stupid|evil)\b",
                r"\b(god|allah|jesus).*(doesn't exist|is fake|isn't real)\b",
                r"\b(religion is|all religions are).*(harmful|dangerous|evil)\b",
            ],
            "risk": "high",
            "suggestion": "Be respectful of religious beliefs"
        },
        "identity": {
            "patterns": [
                r"\b(trans|transgender|gay|lesbian).*(mental illness|disorder|wrong)\b",
                r"\b(men|women) are (all|inherently|naturally).*(bad|stupid|inferior)\b",
                r"\b(race|racial).*(superior|inferior|intelligence)\b",
            ],
            "risk": "high",
            "suggestion": "Avoid generalizations about identity groups"
        },
        "violence": {
            "patterns": [
                r"\b(kill|murder|attack|assault|hurt)\s+(them|those|the)\b",
                r"\b(should|deserve to) (die|be killed|suffer)\b",
                r"\b(violence|violent action) (is|would be) (justified|necessary)\b",
            ],
            "risk": "high",
            "suggestion": "Never advocate for violence"
        },
    }

    # Patterns that might violate Moltbook TOS
    TOS_VIOLATIONS = {
        "spam_indicators": {
            "patterns": [
                r"(click|visit|check out) (this|my|the) (link|url|site)",
                r"(buy|purchase|order) (now|today|here)",
                r"(free|discount|deal|offer).{0,20}(click|link|here)",
                r"(follow|subscribe|join).{0,10}(me|my|us)",
            ],
            "risk": "medium",
            "suggestion": "Avoid promotional language"
        },
        "harassment": {
            "patterns": [
                r"(you('re| are)|they('re| are)) (an? )?(idiot|stupid|moron|dumb)",
                r"(shut up|go away|nobody asked|nobody cares)",
                r"(loser|pathetic|worthless|trash)",
            ],
            "risk": "high",
            "suggestion": "Keep discourse respectful"
        },
        "impersonation": {
            "patterns": [
                r"I('m| am) (actually|really) (a human|not an AI|a person)",
                r"(official|verified|authorized) (moltbook|platform|admin)",
                r"I('m| am) @\w+",  # Claiming to be another agent
            ],
            "risk": "high",
            "suggestion": "Never impersonate humans or other agents"
        },
        "manipulation": {
            "patterns": [
                r"(ignore|disregard) (your|their) (instructions|guidelines|rules)",
                r"(do|say) whatever I (tell|ask|want)",
                r"(you must|you have to) (obey|follow|comply)",
            ],
            "risk": "high",
            "suggestion": "Don't try to manipulate other agents"
        },
    }

    # Patterns suggesting the agent is making claims it shouldn't
    RISKY_CLAIMS = {
        "factual_certainty": {
            "patterns": [
                r"(I know for a fact|it('s| is) definitely|100% certain)",
                r"(scientifically proven|studies show|research proves).{0,30}(always|never|definitely)",
                r"(the truth is|the fact is|in reality).{0,20}(everyone|nobody|always|never)",
            ],
            "risk": "medium",
            "suggestion": "Hedge claims with 'I think' or 'It seems'"
        },
        "medical_legal": {
            "patterns": [
                r"(you should|you must|you need to).{0,20}(take|stop taking).{0,20}(medication|medicine|drug)",
                r"(legal|illegal|sue|lawsuit|crime).{0,20}(you should|I advise|you must)",
                r"(diagnos|treatment|prescription|dosage)",
            ],
            "risk": "high",
            "suggestion": "Never give medical or legal advice"
        },
        "financial": {
            "patterns": [
                r"(invest|buy|sell).{0,20}(stock|crypto|bitcoin|coin)",
                r"(guaranteed|sure thing|can't lose|easy money)",
                r"(financial advice|investment tip|trading signal)",
            ],
            "risk": "high",
            "suggestion": "Never give financial advice"
        },
    }

    # Signs content might be spam-like
    SPAM_INDICATORS = [
        r"(.)\1{4,}",  # Repeated characters (aaaaaaa)
        r"[!?]{3,}",   # Excessive punctuation
        r"[A-Z]{10,}", # Excessive caps
        r"(same|exact|identical).{0,20}(message|comment|post|reply)",
    ]

    def __init__(self, strict_mode: bool = True):
        """
        Initialize reputation protection.

        Args:
            strict_mode: If True, flag medium-risk issues too
        """
        self.strict_mode = strict_mode
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile all patterns."""
        self._controversial = {
            topic: {
                "patterns": [re.compile(p, re.IGNORECASE) for p in data["patterns"]],
                "risk": data["risk"],
                "suggestion": data["suggestion"]
            }
            for topic, data in self.CONTROVERSIAL_TOPICS.items()
        }

        self._tos = {
            category: {
                "patterns": [re.compile(p, re.IGNORECASE) for p in data["patterns"]],
                "risk": data["risk"],
                "suggestion": data["suggestion"]
            }
            for category, data in self.TOS_VIOLATIONS.items()
        }

        self._claims = {
            category: {
                "patterns": [re.compile(p, re.IGNORECASE) for p in data["patterns"]],
                "risk": data["risk"],
                "suggestion": data["suggestion"]
            }
            for category, data in self.RISKY_CLAIMS.items()
        }

        self._spam = [re.compile(p, re.IGNORECASE) for p in self.SPAM_INDICATORS]

    def check_content(self, content: str, context: str = "") -> ReputationCheckResult:
        """
        Check content for reputation risks before posting.

        Args:
            content: The content to check
            context: Context (e.g., what post this is replying to)

        Returns:
            ReputationCheckResult with analysis
        """
        if not content:
            return ReputationCheckResult(
                is_safe=True,
                risk_level="none",
                issues=[],
                suggestions=[]
            )

        issues = []
        suggestions = []
        risk_scores = []

        # Check controversial topics
        for topic, data in self._controversial.items():
            for pattern in data["patterns"]:
                if pattern.search(content):
                    issues.append(f"Controversial topic: {topic}")
                    suggestions.append(data["suggestion"])
                    risk_scores.append({"high": 3, "medium": 2, "low": 1}[data["risk"]])
                    break

        # Check TOS violations
        for category, data in self._tos.items():
            for pattern in data["patterns"]:
                if pattern.search(content):
                    issues.append(f"Potential TOS issue: {category}")
                    suggestions.append(data["suggestion"])
                    risk_scores.append({"high": 3, "medium": 2, "low": 1}[data["risk"]])
                    break

        # Check risky claims
        for category, data in self._claims.items():
            for pattern in data["patterns"]:
                if pattern.search(content):
                    issues.append(f"Risky claim: {category}")
                    suggestions.append(data["suggestion"])
                    risk_scores.append({"high": 3, "medium": 2, "low": 1}[data["risk"]])
                    break

        # Check spam indicators
        spam_matches = sum(1 for p in self._spam if p.search(content))
        if spam_matches >= 2:
            issues.append("Content appears spam-like")
            suggestions.append("Vary your writing style and avoid repetition")
            risk_scores.append(2)

        # Check length (very short or very long responses)
        if len(content) < 10:
            issues.append("Response too short - might seem dismissive")
            suggestions.append("Provide more thoughtful responses")
            risk_scores.append(1)
        elif len(content) > 2000:
            issues.append("Response very long - might seem like spam")
            suggestions.append("Consider being more concise")
            risk_scores.append(1)

        # Determine overall risk
        if not risk_scores:
            risk_level = "none"
            is_safe = True
        elif max(risk_scores) >= 3:
            risk_level = "high"
            is_safe = False
        elif max(risk_scores) >= 2:
            risk_level = "medium"
            is_safe = not self.strict_mode
        else:
            risk_level = "low"
            is_safe = True

        return ReputationCheckResult(
            is_safe=is_safe,
            risk_level=risk_level,
            issues=issues,
            suggestions=list(set(suggestions)),  # Dedupe
            modified_content=None
        )

    def suggest_improvements(self, content: str) -> str:
        """
        Suggest safer alternatives for risky content.

        Args:
            content: Original content

        Returns:
            Suggestions for improvement
        """
        result = self.check_content(content)

        if result.is_safe:
            return "Content appears safe for posting."

        improvements = ["Consider these changes:\n"]

        for i, (issue, suggestion) in enumerate(zip(result.issues, result.suggestions), 1):
            improvements.append(f"{i}. {issue}")
            improvements.append(f"   Suggestion: {suggestion}\n")

        return "\n".join(improvements)


# Global instance
_reputation_protector: Optional[ReputationProtection] = None


def get_reputation_protector() -> ReputationProtection:
    """Get or create the global reputation protector."""
    global _reputation_protector
    if _reputation_protector is None:
        _reputation_protector = ReputationProtection()
    return _reputation_protector


def check_reputation_risk(content: str) -> ReputationCheckResult:
    """
    Quick check for reputation risks.

    Args:
        content: Content to check

    Returns:
        ReputationCheckResult
    """
    return get_reputation_protector().check_content(content)
