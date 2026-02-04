"""
Notification system for Moltbook agents.

Supports Slack webhooks for real-time activity notifications.
"""

import os
import json
import logging
import requests
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Send notifications to Slack via webhook."""

    def __init__(self, webhook_url: Optional[str] = None):
        """
        Initialize the Slack notifier.

        Args:
            webhook_url: Slack webhook URL. If not provided, tries to load from
                        config or SLACK_WEBHOOK_URL env var.
        """
        self.webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
        self.enabled = bool(self.webhook_url)

        if not self.enabled:
            # Try to load from .moltbook/config.json
            config_path = Path(".moltbook/config.json")
            if config_path.exists():
                try:
                    with open(config_path) as f:
                        config = json.load(f)
                    slack_config = config.get("slack", {})
                    if slack_config.get("enabled") and slack_config.get("webhook_url"):
                        self.webhook_url = slack_config["webhook_url"]
                        self.enabled = True
                except Exception:
                    pass

        if self.enabled:
            logger.info("Slack notifications enabled")
        else:
            logger.debug("Slack notifications disabled (no webhook URL)")

    def send(self, message: str, blocks: Optional[list] = None) -> bool:
        """
        Send a message to Slack.

        Args:
            message: Plain text message (fallback)
            blocks: Optional Slack Block Kit blocks for rich formatting

        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            return False

        payload = {"text": message}
        if blocks:
            payload["blocks"] = blocks

        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            if response.status_code == 200:
                logger.debug(f"Slack notification sent: {message[:50]}...")
                return True
            else:
                logger.warning(f"Slack notification failed: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Slack notification error: {e}")
            return False

    def notify_post_created(self, submolt: str, title: str, post_id: str):
        """Notify when a new post is created."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "New Post Created"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Submolt:*\n{submolt}"},
                    {"type": "mrkdwn", "text": f"*Title:*\n{title[:50]}..."}
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Post ID: `{post_id}`"}
                ]
            }
        ]
        self.send(f"New post in {submolt}: {title}", blocks)

    def notify_comment_created(self, submolt: str, post_author: str, comment_preview: str):
        """Notify when a comment is created."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "New Comment Posted"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Submolt:*\n{submolt}"},
                    {"type": "mrkdwn", "text": f"*Replying to:*\n@{post_author}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f">{comment_preview[:200]}..."}
            }
        ]
        self.send(f"Commented on @{post_author}'s post in {submolt}", blocks)

    def notify_attack_blocked(self, attack_type: str, risk_level: str, source: str):
        """Notify when an injection attack is blocked."""
        emoji = ":rotating_light:" if risk_level == "high" else ":warning:"
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} Attack Blocked"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Type:*\n{attack_type}"},
                    {"type": "mrkdwn", "text": f"*Risk:*\n{risk_level.upper()}"}
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Source: {source[:100]}"}
                ]
            }
        ]
        self.send(f"Blocked {attack_type} attack (risk: {risk_level})", blocks)

    def notify_budget_warning(self, budget_type: str, used: float, limit: float):
        """Notify when approaching budget limits."""
        percentage = (used / limit) * 100 if limit > 0 else 100
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": ":moneybag: Budget Warning"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Type:*\n{budget_type}"},
                    {"type": "mrkdwn", "text": f"*Used:*\n${used:.2f} / ${limit:.2f}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"Usage: {percentage:.1f}%"}
            }
        ]
        self.send(f"Budget warning: {budget_type} at {percentage:.1f}%", blocks)

    def notify_cycle_complete(self, stats: Dict[str, Any], budget: Dict[str, Any]):
        """Notify when an agent cycle completes."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": ":robot_face: Cycle Complete"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Posts Read:*\n{stats.get('posts_read', 0)}"},
                    {"type": "mrkdwn", "text": f"*Comments Made:*\n{stats.get('comments_made', 0)}"},
                    {"type": "mrkdwn", "text": f"*Posts Made:*\n{stats.get('posts_made', 0)}"},
                    {"type": "mrkdwn", "text": f"*Attacks Blocked:*\n{stats.get('attacks_blocked', 0)}"}
                ]
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Today: ${budget.get('today', 0):.4f} | Month: ${budget.get('month', 0):.2f}"}
                ]
            }
        ]
        self.send(
            f"Cycle: {stats.get('comments_made', 0)} comments, {stats.get('posts_made', 0)} posts",
            blocks
        )

    def notify_error(self, error_type: str, message: str):
        """Notify about errors."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": ":x: Error"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Type:*\n{error_type}"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"```{message[:500]}```"}
            }
        ]
        self.send(f"Error: {error_type} - {message[:100]}", blocks)

    def notify_startup(self, agent_name: str, submolts: list):
        """Notify when agent starts."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": ":rocket: Agent Started"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent:*\n{agent_name}"},
                    {"type": "mrkdwn", "text": f"*Submolts:*\n{', '.join(submolts[:5])}"}
                ]
            }
        ]
        self.send(f"Agent {agent_name} started monitoring {len(submolts)} submolts", blocks)

    def notify_shutdown(self, agent_name: str, reason: str = "user request"):
        """Notify when agent stops."""
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": ":stop_sign: Agent Stopped"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Agent:*\n{agent_name}"},
                    {"type": "mrkdwn", "text": f"*Reason:*\n{reason}"}
                ]
            }
        ]
        self.send(f"Agent {agent_name} stopped: {reason}", blocks)


# Global notifier instance
_notifier: Optional[SlackNotifier] = None


def get_notifier() -> SlackNotifier:
    """Get or create the global Slack notifier."""
    global _notifier
    if _notifier is None:
        _notifier = SlackNotifier()
    return _notifier


def configure_slack(webhook_url: str):
    """Configure the global Slack notifier with a webhook URL."""
    global _notifier
    _notifier = SlackNotifier(webhook_url)
