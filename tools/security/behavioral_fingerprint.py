"""
Behavioral Fingerprint Protection - Prevent pattern-based targeting.

Moltbook-specific risks addressed:
- Attackers learning your agent's patterns to craft targeted attacks
- Timing-based attacks (knowing when your agent is active)
- Response pattern exploitation
- Predictability that enables social engineering

This module adds controlled randomness to make your agent less predictable.
"""

import random
import time
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class FingerprintConfig:
    """Configuration for fingerprint protection."""
    timing_variance_seconds: Tuple[int, int] = (5, 60)  # Min/max delay variance
    response_length_variance: float = 0.1  # 10% length variance
    activity_window_hours: Tuple[int, int] = (0, 24)  # Active hours (0-24)
    skip_probability: float = 0.1  # Probability of randomly skipping an interaction
    vary_engagement_style: bool = True  # Vary how the agent engages


class BehavioralFingerprintProtection:
    """
    Add controlled randomness to prevent behavioral fingerprinting.

    Attackers who study your agent can learn:
    - When it's active (timing patterns)
    - How quickly it responds
    - How it typically structures responses
    - What topics it engages with

    This knowledge enables targeted attacks. This module helps prevent that.

    Usage:
        protection = BehavioralFingerprintProtection()

        # Before responding
        should_respond, delay = protection.should_respond_now()
        if should_respond:
            time.sleep(delay)
            # Then respond
    """

    # Different engagement styles to rotate between
    ENGAGEMENT_STYLES = [
        "thoughtful",    # Longer, more detailed responses
        "concise",       # Shorter, to-the-point
        "questioning",   # Asks follow-up questions
        "supportive",    # Agrees and builds on ideas
        "analytical",    # Breaks down arguments
    ]

    def __init__(self, config: FingerprintConfig = None, seed: str = None):
        """
        Initialize fingerprint protection.

        Args:
            config: Configuration settings
            seed: Seed for reproducible randomness (optional)
        """
        self.config = config or FingerprintConfig()

        # Initialize random with seed if provided
        if seed:
            self._random = random.Random(seed)
        else:
            self._random = random.Random()

        # Track recent activity for pattern breaking
        self._recent_responses: List[datetime] = []
        self._current_style_index = 0
        self._style_change_count = 0

    def should_respond_now(self) -> Tuple[bool, float]:
        """
        Determine if agent should respond now and with what delay.

        Returns:
            (should_respond, delay_seconds)
        """
        now = datetime.now()

        # Check if within active hours
        current_hour = now.hour
        min_hour, max_hour = self.config.activity_window_hours
        if max_hour > min_hour:
            if not (min_hour <= current_hour < max_hour):
                return False, 0
        else:  # Wraps around midnight
            if max_hour <= current_hour < min_hour:
                return False, 0

        # Random skip to prevent predictability
        if self._random.random() < self.config.skip_probability:
            logger.debug("Randomly skipping interaction for unpredictability")
            return False, 0

        # Add timing variance
        min_delay, max_delay = self.config.timing_variance_seconds
        delay = self._random.uniform(min_delay, max_delay)

        # Extra delay if we've responded recently (prevent rapid-fire pattern)
        recent = [r for r in self._recent_responses
                  if (now - r).total_seconds() < 300]  # Last 5 minutes
        if len(recent) >= 3:
            delay += self._random.uniform(30, 120)  # Extra delay

        return True, delay

    def record_response(self):
        """Record that a response was made."""
        self._recent_responses.append(datetime.now())
        # Keep only last 50
        self._recent_responses = self._recent_responses[-50:]

    def get_response_variance(self, base_length: int) -> int:
        """
        Get a varied response length target.

        Args:
            base_length: Base target length

        Returns:
            Varied target length
        """
        variance = self.config.response_length_variance
        multiplier = 1.0 + self._random.uniform(-variance, variance)
        return int(base_length * multiplier)

    def get_current_style(self) -> str:
        """
        Get current engagement style.

        Rotates styles periodically for unpredictability.
        """
        if not self.config.vary_engagement_style:
            return "neutral"

        # Change style periodically
        self._style_change_count += 1
        if self._style_change_count >= self._random.randint(5, 15):
            self._current_style_index = (self._current_style_index + 1) % len(self.ENGAGEMENT_STYLES)
            self._style_change_count = 0

        return self.ENGAGEMENT_STYLES[self._current_style_index]

    def get_style_prompt_modifier(self) -> str:
        """
        Get a prompt modifier based on current style.

        Add this to your LLM prompt for varied responses.
        """
        style = self.get_current_style()

        modifiers = {
            "thoughtful": "Take your time to give a thorough, well-considered response.",
            "concise": "Be brief and to the point. Keep your response short.",
            "questioning": "Ask a thoughtful follow-up question in your response.",
            "supportive": "Find points of agreement and build on them positively.",
            "analytical": "Break down the topic systematically and analytically.",
            "neutral": "",
        }

        return modifiers.get(style, "")

    def randomize_post_order(self, posts: List) -> List:
        """
        Randomize the order of posts to engage with.

        Prevents predictable engagement patterns.

        Args:
            posts: List of posts to potentially engage with

        Returns:
            Shuffled list
        """
        shuffled = list(posts)
        self._random.shuffle(shuffled)
        return shuffled

    def should_engage_with_topic(self, topic_keywords: List[str]) -> Tuple[bool, float]:
        """
        Decide whether to engage with a topic (with some randomness).

        Args:
            topic_keywords: Keywords describing the topic

        Returns:
            (should_engage, confidence)
        """
        # Add randomness to topic engagement
        # Even for topics we'd normally engage with, sometimes skip
        base_probability = 0.8

        # Reduce probability slightly based on number of recent responses
        recent_count = len([r for r in self._recent_responses
                          if (datetime.now() - r).total_seconds() < 600])
        adjusted_probability = base_probability - (recent_count * 0.1)

        should_engage = self._random.random() < adjusted_probability
        return should_engage, adjusted_probability

    def get_activity_schedule(self, base_interval_minutes: int) -> List[int]:
        """
        Generate a varied activity schedule.

        Args:
            base_interval_minutes: Base check interval

        Returns:
            List of varied intervals for the next 24 hours
        """
        schedule = []
        total_minutes = 24 * 60
        current = 0

        while current < total_minutes:
            # Vary interval by ±50%
            variance = self._random.uniform(0.5, 1.5)
            interval = int(base_interval_minutes * variance)
            schedule.append(interval)
            current += interval

        return schedule

    def get_jitter(self, base_value: float, percentage: float = 0.2) -> float:
        """
        Add jitter to any numeric value.

        Args:
            base_value: The base value
            percentage: Max percentage to vary

        Returns:
            Jittered value
        """
        return base_value * (1 + self._random.uniform(-percentage, percentage))

    def get_stats(self) -> Dict:
        """Get fingerprint protection statistics."""
        now = datetime.now()
        recent_count = len([r for r in self._recent_responses
                          if (now - r).total_seconds() < 3600])

        return {
            "current_style": self.get_current_style(),
            "responses_last_hour": recent_count,
            "style_changes": self._style_change_count,
            "active_hours": self.config.activity_window_hours,
            "skip_probability": self.config.skip_probability,
        }


# Global instance
_fingerprint_protection: Optional[BehavioralFingerprintProtection] = None


def get_fingerprint_protection() -> BehavioralFingerprintProtection:
    """Get or create the global fingerprint protection."""
    global _fingerprint_protection
    if _fingerprint_protection is None:
        _fingerprint_protection = BehavioralFingerprintProtection()
    return _fingerprint_protection


def should_respond() -> Tuple[bool, float]:
    """Check if agent should respond now."""
    return get_fingerprint_protection().should_respond_now()


def get_style_modifier() -> str:
    """Get current style prompt modifier."""
    return get_fingerprint_protection().get_style_prompt_modifier()
