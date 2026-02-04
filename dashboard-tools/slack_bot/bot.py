"""
Slack Bot for sending Moltbook activity notifications
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Optional, Dict, Any, List
import aiohttp
import logging

logger = logging.getLogger(__name__)


class SlackBot:
    """Sends notifications and content to Slack"""

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        channel: Optional[str] = None,
        bot_name: str = "MyAgent"
    ):
        self.webhook_url = webhook_url or os.environ.get('SLACK_WEBHOOK_URL')
        self.channel = channel
        self.bot_name = bot_name

        if not self.webhook_url:
            logger.warning("No Slack webhook URL provided - messages will not be sent")

    async def send_message(
        self,
        text: str,
        blocks: Optional[List[dict]] = None,
        attachments: Optional[List[dict]] = None
    ) -> bool:
        """Send a message to Slack"""
        if not self.webhook_url:
            logger.error("No webhook URL configured")
            return False

        payload = {"text": text}
        if blocks:
            payload["blocks"] = blocks
        if attachments:
            payload["attachments"] = attachments
        if self.channel:
            payload["channel"] = self.channel

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                ) as resp:
                    if resp.status == 200:
                        logger.info("Message sent to Slack successfully")
                        return True
                    else:
                        logger.error(f"Slack API error: {resp.status} - {await resp.text()}")
                        return False
        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            return False

    def _format_activity_blocks(
        self,
        activity: 'Activity',
        x_content: Optional[str] = None,
        linkedin_content: Optional[str] = None,
        screenshot_url: Optional[str] = None
    ) -> List[dict]:
        """Format activity into Slack blocks"""
        blocks = []

        # Header
        emoji = "📝" if activity.type == "post" else "💬" if activity.type == "comment" else "🎯"
        activity_type = activity.type.upper()

        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🤖 {self.bot_name} Activity",
                "emoji": True
            }
        })

        # Activity details
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"{emoji} *{activity_type}* in m/{activity.community}"
            }
        })

        blocks.append({"type": "divider"})

        # Content preview
        content_preview = activity.content[:300] + "..." if len(activity.content) > 300 else activity.content
        if activity.title:
            content_preview = f"*{activity.title}*\n\n{content_preview}"

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"```{content_preview}```"
            }
        })

        # Engagement stats
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"📊 *{activity.upvotes}* upvotes  •  *{activity.comments_count}* comments  •  <{activity.url}|View on Moltbook>"
                }
            ]
        })

        blocks.append({"type": "divider"})

        # X content section
        if x_content:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*🐦 READY FOR X:*"
                }
            })
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{x_content}```"
                }
            })
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📋 Copy X Post"},
                        "value": "copy_x",
                        "action_id": "copy_x_content"
                    }
                ]
            })

            blocks.append({"type": "divider"})

        # LinkedIn content section
        if linkedin_content:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*💼 READY FOR LINKEDIN:*"
                }
            })
            # LinkedIn content can be longer, so truncate if needed for Slack
            li_preview = linkedin_content[:2000] + "..." if len(linkedin_content) > 2000 else linkedin_content
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{li_preview}```"
                }
            })
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📋 Copy LinkedIn Post"},
                        "value": "copy_linkedin",
                        "action_id": "copy_linkedin_content"
                    }
                ]
            })

        # Screenshot
        if screenshot_url:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "image",
                "image_url": screenshot_url,
                "alt_text": "Moltbook screenshot"
            })

        return blocks

    async def send_activity_notification(
        self,
        activity: 'Activity',
        x_content: Optional[str] = None,
        linkedin_content: Optional[str] = None,
        screenshot_url: Optional[str] = None
    ) -> bool:
        """Send a formatted activity notification"""
        blocks = self._format_activity_blocks(
            activity,
            x_content,
            linkedin_content,
            screenshot_url
        )

        fallback_text = f"New {activity.type} by {self.bot_name} in m/{activity.community}"
        return await self.send_message(fallback_text, blocks=blocks)

    async def send_daily_summary(
        self,
        stats: Dict[str, Any],
        x_content: Optional[str] = None,
        linkedin_content: Optional[str] = None,
        day_number: int = 1
    ) -> bool:
        """Send daily summary to Slack"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"📊 Day {day_number} Summary - {self.bot_name}",
                    "emoji": True
                }
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Posts Today:*\n{stats.get('posts_today', 0)}"},
                    {"type": "mrkdwn", "text": f"*Comments Today:*\n{stats.get('comments_today', 0)}"},
                    {"type": "mrkdwn", "text": f"*Total Karma:*\n{stats.get('current_karma', 0)}"},
                    {"type": "mrkdwn", "text": f"*Communities:*\n{stats.get('communities_active', 0)}"}
                ]
            },
            {"type": "divider"}
        ]

        if x_content:
            blocks.extend([
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "*🐦 X Summary Post:*"}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"```{x_content}```"}
                }
            ])

        if linkedin_content:
            blocks.extend([
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "*💼 LinkedIn Summary Post:*"}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"```{linkedin_content[:1500]}```"}
                }
            ])

        return await self.send_message(
            f"Day {day_number} Summary for {self.bot_name}",
            blocks=blocks
        )

    async def send_milestone(
        self,
        milestone: str,
        value: int,
        x_content: Optional[str] = None,
        linkedin_content: Optional[str] = None
    ) -> bool:
        """Send milestone notification"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🎉 Milestone Reached!",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{milestone}*: {value}"
                }
            },
            {"type": "divider"}
        ]

        if x_content:
            blocks.extend([
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*🐦 X Post:*\n```{x_content}```"}
                }
            ])

        if linkedin_content:
            blocks.extend([
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*💼 LinkedIn Post:*\n```{linkedin_content[:1500]}```"}
                }
            ])

        return await self.send_message(
            f"Milestone: {milestone}",
            blocks=blocks
        )

    async def send_high_engagement_alert(
        self,
        activity: 'Activity',
        x_content: Optional[str] = None,
        linkedin_content: Optional[str] = None
    ) -> bool:
        """Send alert for high engagement content"""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🔥 High Engagement Alert!",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"This {activity.type} is performing well!"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Upvotes:* {activity.upvotes}"},
                    {"type": "mrkdwn", "text": f"*Comments:* {activity.comments_count}"},
                    {"type": "mrkdwn", "text": f"*Community:* m/{activity.community}"}
                ]
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"```{activity.content[:500]}```"}
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"<{activity.url}|View on Moltbook>"}
                ]
            }
        ]

        if x_content:
            blocks.extend([
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*🐦 X Post:*\n```{x_content}```"}
                }
            ])

        if linkedin_content:
            blocks.extend([
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*💼 LinkedIn Post:*\n```{linkedin_content[:1500]}```"}
                }
            ])

        return await self.send_message(
            f"High engagement alert: {activity.upvotes} upvotes",
            blocks=blocks
        )


# Convenience function for quick messages
async def send_quick_slack(message: str, webhook_url: Optional[str] = None) -> bool:
    """Send a quick message to Slack"""
    bot = SlackBot(webhook_url=webhook_url)
    return await bot.send_message(message)
