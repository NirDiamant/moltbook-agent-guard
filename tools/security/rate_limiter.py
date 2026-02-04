"""
Persistent Rate Limiter - Rate limiting that survives restarts.

Stores rate limit state in a JSON file so limits persist across
agent restarts. This prevents attackers from bypassing rate limits
by simply restarting your agent.

Features:
- Per-action rate limiting (posts, comments, requests)
- Sliding window implementation
- Persistent state storage
- Configurable limits
- Automatic cleanup of old entries
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass, asdict
from threading import Lock
import logging

logger = logging.getLogger(__name__)


@dataclass
class RateLimitResult:
    """Result of a rate limit check."""
    allowed: bool
    action: str
    current_count: int
    limit: int
    window_seconds: int
    retry_after: Optional[int] = None
    message: str = ""


@dataclass
class RateLimitConfig:
    """Configuration for a rate limit."""
    limit: int  # Maximum allowed in window
    window_seconds: int  # Time window in seconds
    cooldown_seconds: int = 0  # Minimum time between actions


class PersistentRateLimiter:
    """
    Rate limiter with persistent state storage.

    Usage:
        limiter = PersistentRateLimiter()

        # Check before taking action
        result = limiter.check("comment")
        if result.allowed:
            # Do the action
            limiter.record("comment")
        else:
            print(f"Rate limited. Retry after {result.retry_after}s")
    """

    # Default rate limits
    DEFAULT_LIMITS: Dict[str, RateLimitConfig] = {
        "post": RateLimitConfig(
            limit=5,
            window_seconds=86400,  # 5 posts per day
            cooldown_seconds=1800  # 30 min between posts
        ),
        "comment": RateLimitConfig(
            limit=50,
            window_seconds=86400,  # 50 comments per day
            cooldown_seconds=20   # 20 sec between comments
        ),
        "request": RateLimitConfig(
            limit=100,
            window_seconds=60,     # 100 requests per minute
            cooldown_seconds=0
        ),
        "vote": RateLimitConfig(
            limit=100,
            window_seconds=3600,   # 100 votes per hour
            cooldown_seconds=1
        ),
        "api_call": RateLimitConfig(
            limit=1000,
            window_seconds=3600,   # 1000 API calls per hour
            cooldown_seconds=0
        ),
    }

    def __init__(self, state_file: str = None,
                 custom_limits: Dict[str, RateLimitConfig] = None):
        """
        Initialize the rate limiter.

        Args:
            state_file: Path to state file (default: .moltbook/rate_state.json)
            custom_limits: Custom rate limits to override defaults
        """
        self.state_file = Path(state_file or ".moltbook/rate_state.json")
        self.state_file.parent.mkdir(parents=True, exist_ok=True)

        self.limits = dict(self.DEFAULT_LIMITS)
        if custom_limits:
            self.limits.update(custom_limits)

        self._lock = Lock()
        self._state = self._load_state()

    def _load_state(self) -> Dict:
        """Load state from disk."""
        if not self.state_file.exists():
            return {"actions": {}, "last_save": time.time()}

        try:
            with open(self.state_file) as f:
                state = json.load(f)
                # Clean up old entries
                self._cleanup_state(state)
                return state
        except Exception as e:
            logger.warning(f"Failed to load rate limit state: {e}")
            return {"actions": {}, "last_save": time.time()}

    def _save_state(self):
        """Save state to disk."""
        try:
            self._state["last_save"] = time.time()
            with open(self.state_file, 'w') as f:
                json.dump(self._state, f)
        except Exception as e:
            logger.error(f"Failed to save rate limit state: {e}")

    def _cleanup_state(self, state: Dict):
        """Remove entries older than the longest window."""
        now = time.time()
        max_window = max(cfg.window_seconds for cfg in self.limits.values())

        for action, timestamps in list(state.get("actions", {}).items()):
            # Filter out old timestamps
            state["actions"][action] = [
                ts for ts in timestamps
                if now - ts < max_window
            ]
            # Remove empty entries
            if not state["actions"][action]:
                del state["actions"][action]

    def check(self, action: str) -> RateLimitResult:
        """
        Check if an action is allowed under rate limits.

        Args:
            action: The action type (e.g., "post", "comment")

        Returns:
            RateLimitResult indicating if action is allowed
        """
        if action not in self.limits:
            # Unknown action - allow with warning
            logger.warning(f"Unknown rate limit action: {action}")
            return RateLimitResult(
                allowed=True,
                action=action,
                current_count=0,
                limit=0,
                window_seconds=0,
                message="Unknown action type - no limit applied"
            )

        config = self.limits[action]
        now = time.time()

        with self._lock:
            timestamps = self._state.get("actions", {}).get(action, [])

            # Filter to current window
            window_start = now - config.window_seconds
            recent = [ts for ts in timestamps if ts > window_start]
            count = len(recent)

            # Check window limit
            if count >= config.limit:
                # Find when oldest entry expires
                oldest = min(recent) if recent else now
                retry_after = int(oldest + config.window_seconds - now) + 1

                return RateLimitResult(
                    allowed=False,
                    action=action,
                    current_count=count,
                    limit=config.limit,
                    window_seconds=config.window_seconds,
                    retry_after=retry_after,
                    message=f"Rate limit exceeded: {count}/{config.limit} in {config.window_seconds}s"
                )

            # Check cooldown
            if config.cooldown_seconds > 0 and recent:
                last_action = max(recent)
                elapsed = now - last_action
                if elapsed < config.cooldown_seconds:
                    retry_after = int(config.cooldown_seconds - elapsed) + 1
                    return RateLimitResult(
                        allowed=False,
                        action=action,
                        current_count=count,
                        limit=config.limit,
                        window_seconds=config.window_seconds,
                        retry_after=retry_after,
                        message=f"Cooldown active: wait {retry_after}s between {action}s"
                    )

            return RateLimitResult(
                allowed=True,
                action=action,
                current_count=count,
                limit=config.limit,
                window_seconds=config.window_seconds,
                message=f"Allowed: {count}/{config.limit} used"
            )

    def record(self, action: str) -> None:
        """
        Record that an action was taken.

        Args:
            action: The action type
        """
        with self._lock:
            if "actions" not in self._state:
                self._state["actions"] = {}

            if action not in self._state["actions"]:
                self._state["actions"][action] = []

            self._state["actions"][action].append(time.time())

            # Periodic cleanup and save
            if time.time() - self._state.get("last_save", 0) > 60:
                self._cleanup_state(self._state)
                self._save_state()

    def check_and_record(self, action: str) -> RateLimitResult:
        """
        Check if action is allowed and record it if so.

        Args:
            action: The action type

        Returns:
            RateLimitResult
        """
        result = self.check(action)
        if result.allowed:
            self.record(action)
        return result

    def get_status(self, action: str = None) -> Dict:
        """
        Get current rate limit status.

        Args:
            action: Specific action, or None for all

        Returns:
            Status dictionary
        """
        now = time.time()
        status = {}

        actions = [action] if action else self.limits.keys()

        for act in actions:
            if act not in self.limits:
                continue

            config = self.limits[act]
            timestamps = self._state.get("actions", {}).get(act, [])
            window_start = now - config.window_seconds
            recent = [ts for ts in timestamps if ts > window_start]

            status[act] = {
                "current_count": len(recent),
                "limit": config.limit,
                "window_seconds": config.window_seconds,
                "cooldown_seconds": config.cooldown_seconds,
                "remaining": config.limit - len(recent),
                "resets_in": int(config.window_seconds - (now - min(recent))) if recent else 0
            }

        return status if not action else status.get(action, {})

    def reset(self, action: str = None) -> None:
        """
        Reset rate limit counters.

        Args:
            action: Specific action to reset, or None for all
        """
        with self._lock:
            if action:
                self._state.get("actions", {}).pop(action, None)
            else:
                self._state["actions"] = {}
            self._save_state()

    def set_limit(self, action: str, limit: int = None,
                  window_seconds: int = None, cooldown_seconds: int = None) -> None:
        """
        Update rate limit configuration.

        Args:
            action: Action to configure
            limit: New limit (or None to keep current)
            window_seconds: New window (or None to keep current)
            cooldown_seconds: New cooldown (or None to keep current)
        """
        if action in self.limits:
            current = self.limits[action]
            self.limits[action] = RateLimitConfig(
                limit=limit if limit is not None else current.limit,
                window_seconds=window_seconds if window_seconds is not None else current.window_seconds,
                cooldown_seconds=cooldown_seconds if cooldown_seconds is not None else current.cooldown_seconds
            )
        else:
            self.limits[action] = RateLimitConfig(
                limit=limit or 100,
                window_seconds=window_seconds or 3600,
                cooldown_seconds=cooldown_seconds or 0
            )


# Global instance
_rate_limiter: Optional[PersistentRateLimiter] = None


def get_rate_limiter() -> PersistentRateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = PersistentRateLimiter()
    return _rate_limiter


def check_rate_limit(action: str) -> RateLimitResult:
    """
    Check if an action is allowed.

    Args:
        action: Action type

    Returns:
        RateLimitResult
    """
    return get_rate_limiter().check(action)


def record_action(action: str) -> None:
    """
    Record that an action was taken.

    Args:
        action: Action type
    """
    get_rate_limiter().record(action)
