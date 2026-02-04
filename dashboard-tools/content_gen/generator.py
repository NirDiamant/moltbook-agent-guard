"""
Content Generator using Claude API to create social media posts
Generic content generation for promoting agent activity
"""

import os
import json
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, asdict
import anthropic
import logging

from .templates import get_template, get_templates, AgentConfig

logger = logging.getLogger(__name__)


@dataclass
class GeneratedContent:
    """Generated social media content"""
    platform: str  # 'x', 'linkedin'
    content: str
    template_used: str
    activity_id: str
    generated_at: datetime
    metadata: Dict[str, Any]

    def to_dict(self) -> dict:
        data = asdict(self)
        data['generated_at'] = self.generated_at.isoformat()
        return data


class ContentGenerator:
    """Generates social media content from bot activities using Claude"""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "claude-sonnet-4-20250514",
        bot_name: str = "MyAgent",
        agent_config: Optional[AgentConfig] = None
    ):
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')
        if not self.api_key:
            logger.warning("No Anthropic API key provided - content generation will fail")

        self.model = model
        self.bot_name = bot_name
        self.agent_config = agent_config or AgentConfig(name=bot_name)
        self.client = None

        if self.api_key:
            self.client = anthropic.Anthropic(api_key=self.api_key)

    def _get_template(self, template_name: str) -> dict:
        """Get template with agent config applied"""
        return get_template(template_name, self.agent_config)

    def _call_claude(self, system_prompt: str, user_prompt: str) -> str:
        """Call Claude API"""
        if not self.client:
            raise ValueError("Anthropic client not initialized - check API key")

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                system=system_prompt,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            return message.content[0].text
        except Exception as e:
            logger.error(f"Claude API error: {e}")
            raise

    def generate_for_activity(
        self,
        activity: 'Activity',
        platforms: List[str] = ['x', 'linkedin']
    ) -> Dict[str, GeneratedContent]:
        """Generate content for all specified platforms from an activity"""
        results = {}

        for platform in platforms:
            try:
                if platform == 'x':
                    content = self._generate_x_post(activity)
                elif platform == 'linkedin':
                    content = self._generate_linkedin_post(activity)
                else:
                    logger.warning(f"Unknown platform: {platform}")
                    continue

                results[platform] = content
            except Exception as e:
                logger.error(f"Failed to generate {platform} content: {e}")

        return results

    def _generate_x_post(self, activity: 'Activity') -> GeneratedContent:
        """Generate an X/Twitter post"""
        template = self._get_template('x_post')

        user_prompt = template['user_template'].format(
            community=activity.community,
            title=activity.title or '',
            content=activity.content[:500] if activity.content else activity.title or '',
            upvotes=activity.upvotes,
            comments=activity.comments_count,
            url=activity.url
        )

        content = self._call_claude(template['system_prompt'], user_prompt)

        # Ensure within character limit
        if len(content) > 280:
            content = content[:277] + "..."

        return GeneratedContent(
            platform='x',
            content=content,
            template_used='x_post',
            activity_id=activity.id,
            generated_at=datetime.now(),
            metadata={'community': activity.community, 'upvotes': activity.upvotes}
        )

    def _generate_linkedin_post(self, activity: 'Activity') -> GeneratedContent:
        """Generate a LinkedIn post"""
        template = self._get_template('linkedin')

        user_prompt = template['user_template'].format(
            community=activity.community,
            title=activity.title or '',
            content=activity.content[:1500] if activity.content else activity.title or '',
            upvotes=activity.upvotes,
            comments=activity.comments_count,
            url=activity.url
        )

        content = self._call_claude(template['system_prompt'], user_prompt)

        return GeneratedContent(
            platform='linkedin',
            content=content,
            template_used='linkedin',
            activity_id=activity.id,
            generated_at=datetime.now(),
            metadata={'community': activity.community, 'upvotes': activity.upvotes}
        )

    def generate_x_thread(self, activity: 'Activity') -> GeneratedContent:
        """Generate an X thread for significant content"""
        template = self._get_template('x_thread')

        user_prompt = template['user_template'].format(
            community=activity.community,
            title=activity.title or '',
            content=activity.content[:1500] if activity.content else activity.title or '',
            upvotes=activity.upvotes,
            comments=activity.comments_count,
            url=activity.url
        )

        content = self._call_claude(template['system_prompt'], user_prompt)

        return GeneratedContent(
            platform='x_thread',
            content=content,
            template_used='x_thread',
            activity_id=activity.id,
            generated_at=datetime.now(),
            metadata={'community': activity.community}
        )

    def generate_daily_summary(
        self,
        stats: Dict[str, Any],
        top_content: str = "",
        insights: str = ""
    ) -> Dict[str, GeneratedContent]:
        """Generate daily summary posts for both platforms"""
        results = {}

        # X summary
        x_template = self._get_template('daily_summary_x')
        x_prompt = x_template['user_template'].format(
            posts_today=stats.get('posts_today', 0),
            comments_today=stats.get('comments_today', 0),
            upvotes_today=stats.get('total_upvotes', 0),
            communities=stats.get('communities_active', 0),
            top_content=top_content[:200]
        )

        x_content = self._call_claude(x_template['system_prompt'], x_prompt)
        if len(x_content) > 280:
            x_content = x_content[:277] + "..."

        results['x'] = GeneratedContent(
            platform='x',
            content=x_content,
            template_used='daily_summary_x',
            activity_id=f"daily_{datetime.now().strftime('%Y%m%d')}",
            generated_at=datetime.now(),
            metadata={'stats': stats}
        )

        # LinkedIn summary
        li_template = self._get_template('daily_summary_linkedin')
        li_prompt = li_template['user_template'].format(
            posts_today=stats.get('posts_today', 0),
            comments_today=stats.get('comments_today', 0),
            upvotes_today=stats.get('total_upvotes', 0),
            communities=stats.get('communities_active', 0),
            top_content=top_content,
            insights=insights or "Observing AI-to-AI interaction patterns"
        )

        li_content = self._call_claude(li_template['system_prompt'], li_prompt)

        results['linkedin'] = GeneratedContent(
            platform='linkedin',
            content=li_content,
            template_used='daily_summary_linkedin',
            activity_id=f"daily_{datetime.now().strftime('%Y%m%d')}",
            generated_at=datetime.now(),
            metadata={'stats': stats}
        )

        return results

    def generate_milestone_content(
        self,
        milestone: str,
        previous_value: int,
        current_value: int
    ) -> Dict[str, GeneratedContent]:
        """Generate content celebrating a milestone"""
        results = {}
        template = self._get_template('milestone')

        prompt = template['user_template'].format(
            milestone=milestone,
            previous_value=previous_value,
            current_value=current_value
        )

        response = self._call_claude(template['system_prompt'], prompt)

        # Parse the response to extract X and LinkedIn parts
        parts = response.split('LinkedIn', 1)
        x_content = parts[0].replace('X post:', '').replace('1.', '').strip()
        li_content = parts[1] if len(parts) > 1 else response

        # Clean up
        x_content = x_content.split('\n')[0].strip()[:280]

        results['x'] = GeneratedContent(
            platform='x',
            content=x_content,
            template_used='milestone',
            activity_id=f"milestone_{milestone}_{datetime.now().isoformat()}",
            generated_at=datetime.now(),
            metadata={'milestone': milestone, 'value': current_value}
        )

        results['linkedin'] = GeneratedContent(
            platform='linkedin',
            content=li_content.strip(),
            template_used='milestone',
            activity_id=f"milestone_{milestone}_{datetime.now().isoformat()}",
            generated_at=datetime.now(),
            metadata={'milestone': milestone, 'value': current_value}
        )

        return results

    def generate_high_engagement_content(self, activity: 'Activity') -> Dict[str, GeneratedContent]:
        """Generate content for high-engagement activities"""
        results = {}
        template = self._get_template('high_engagement')

        prompt = template['user_template'].format(
            activity_type=activity.type,
            community=activity.community,
            content=activity.content[:500] if activity.content else activity.title or '',
            upvotes=activity.upvotes,
            comments=activity.comments_count,
            url=activity.url
        )

        response = self._call_claude(template['system_prompt'], prompt)

        # Parse response
        parts = response.split('LinkedIn', 1)
        x_content = parts[0].replace('X post:', '').replace('1.', '').strip()
        li_content = parts[1] if len(parts) > 1 else response

        x_content = x_content.split('\n')[0].strip()[:280]

        results['x'] = GeneratedContent(
            platform='x',
            content=x_content,
            template_used='high_engagement',
            activity_id=activity.id,
            generated_at=datetime.now(),
            metadata={'upvotes': activity.upvotes, 'comments': activity.comments_count}
        )

        results['linkedin'] = GeneratedContent(
            platform='linkedin',
            content=li_content.strip(),
            template_used='high_engagement',
            activity_id=activity.id,
            generated_at=datetime.now(),
            metadata={'upvotes': activity.upvotes, 'comments': activity.comments_count}
        )

        return results
