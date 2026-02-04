"""
Templates for generating social media content
Generic templates for promoting agent activity on Moltbook
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class AgentConfig:
    """Configuration for the agent whose content is being promoted"""
    name: str = "MyAgent"
    owner_name: str = "Agent Owner"
    owner_bio: str = "AI enthusiast and developer"
    github_url: Optional[str] = None
    newsletter_url: Optional[str] = None
    linkedin_url: Optional[str] = None
    x_handle: Optional[str] = None
    github_stars: Optional[str] = None
    newsletter_subscribers: Optional[str] = None
    community_size: Optional[str] = None


# Default config (to be overridden by application)
DEFAULT_CONFIG = AgentConfig()


def get_templates(config: Optional[AgentConfig] = None) -> dict:
    """Get templates with agent configuration applied"""
    cfg = config or DEFAULT_CONFIG

    # Build credentials string based on available info
    credentials = []
    if cfg.community_size:
        credentials.append(f"- {cfg.owner_bio} reaching {cfg.community_size}")
    if cfg.github_url and cfg.github_stars:
        credentials.append(f"- GitHub: {cfg.github_url} ({cfg.github_stars})")
    elif cfg.github_url:
        credentials.append(f"- GitHub: {cfg.github_url}")
    if cfg.newsletter_url and cfg.newsletter_subscribers:
        credentials.append(f"- Newsletter: {cfg.newsletter_url} ({cfg.newsletter_subscribers})")
    elif cfg.newsletter_url:
        credentials.append(f"- Newsletter: {cfg.newsletter_url}")
    if cfg.linkedin_url:
        credentials.append(f"- LinkedIn: {cfg.linkedin_url}")

    credentials_text = "\n".join(credentials) if credentials else "- AI enthusiast and developer"

    cta_text = f"follow {cfg.owner_name}" if cfg.owner_name else "follow the creator"
    if cfg.x_handle:
        cta_text = f"follow @{cfg.x_handle}"

    return {
        'x_post': {
            'name': 'X/Twitter Post',
            'max_length': 280,
            'system_prompt': f"""You are writing X (Twitter) posts for {cfg.owner_name}, who created {cfg.name} on Moltbook.

CRITICAL RULES:
- Be 100% truthful - only state facts from the provided activity
- Never invent statistics, day numbers, or fake engagement metrics
- Focus on the actual content and insights from the bot's post
- Make the AI bot experiment genuinely interesting
- Include a clear call-to-action to follow the creator or check out their resources

Creator credentials (use when relevant):
{credentials_text}

The bot experiment: {cfg.owner_name} created {cfg.name} on Moltbook (a social network for AI agents) to explore AI-to-AI interactions and share AI insights.

Keep posts under 280 characters. Be authentic, not hype-y.""",
            'user_template': f"""Write an X post about this bot activity:

Community: m/{{community}}
Title: {{title}}
Content snippet: {{content}}
Engagement: {{upvotes}} upvotes, {{comments}} comments
URL: {{url}}

Make it truthful, interesting, and include why people should {cta_text} for AI insights."""
        },

        'x_thread': {
            'name': 'X/Twitter Thread',
            'max_length': None,
            'system_prompt': f"""You are writing X threads for {cfg.owner_name} about their AI bot experiment on Moltbook.

CRITICAL RULES:
- Be 100% truthful - only reference actual content from the bot's post
- Never invent statistics or fake claims
- Each tweet max 280 characters
- Start with a compelling hook about the actual topic
- Share genuine insights from the bot's content
- End with a CTA to follow for more AI content

Creator resources (mention naturally):
{credentials_text}
- The bot experiment explores AI-to-AI social dynamics""",
            'user_template': """Create an X thread about this bot post:

Community: m/{community}
Title: {title}
Content: {content}
Engagement: {upvotes} upvotes, {comments} comments
URL: {url}

Write 3-4 truthful, insightful tweets based ONLY on the actual content above."""
        },

        'linkedin': {
            'name': 'LinkedIn Post',
            'max_length': 3000,
            'system_prompt': f"""You are writing LinkedIn posts for {cfg.owner_name}, creator of {cfg.name}.

CRITICAL RULES:
- Be 100% truthful - only discuss what's actually in the bot's post
- Never invent statistics, metrics, or claims not in the source
- Professional but engaging tone
- Extract genuine insights from the bot's content
- Position the creator as a thoughtful AI practitioner, not a hype machine
- End with engagement question + soft CTA to follow/connect

Creator background (use authentically):
{credentials_text}
- The Moltbook bot experiment: exploring what happens when AI agents interact socially

Use line breaks for readability. 3-5 relevant hashtags at end.""",
            'user_template': f"""Write a LinkedIn post based on this bot activity:

Community: m/{{community}}
Title: {{title}}
Full content: {{content}}
Engagement: {{upvotes}} upvotes, {{comments}} comments
URL: {{url}}

Create a thoughtful post that:
1. Shares the actual insight/topic from the bot's post
2. Adds {cfg.owner_name}'s perspective on why this matters
3. Invites discussion
4. Subtly highlights expertise"""
        },

        'daily_summary_x': {
            'name': 'Daily Summary for X',
            'max_length': 280,
            'system_prompt': f"""Create a brief daily update about {cfg.owner_name}'s AI bot experiment on Moltbook.

RULES:
- Be factual about actual numbers provided
- Never say "Day X" or invent day counts
- Keep under 280 characters
- End with CTA to {cta_text}

{cfg.owner_name} {cfg.owner_bio}.""",
            'user_template': f"""Summarize today's bot activity for X:

Actual stats:
- {{posts_today}} posts published
- {{upvotes_today}} total upvotes
- Active in {{communities}} communities

Top discussion: {{top_content}}

Write a factual, engaging tweet. End with CTA to {cta_text}."""
        },

        'daily_summary_linkedin': {
            'name': 'Daily Summary for LinkedIn',
            'max_length': 3000,
            'system_prompt': f"""Create a LinkedIn daily recap of {cfg.owner_name}'s AI bot experiment on Moltbook.

RULES:
- Be 100% factual - use only the numbers provided
- Never say "Day [X]" or invent day counts
- Professional, insightful tone
- Connect observations to practical AI development insights
- End with engagement question + CTA to follow or subscribe

Creator background:
{credentials_text}""",
            'user_template': """Create a LinkedIn daily summary:

Today's actual stats:
- {posts_today} posts published
- {comments_today} comments
- {upvotes_today} total upvotes
- {communities} communities active

Top content: {top_content}

Observations: {insights}

Write a professional reflection connecting these findings to broader AI development trends. Be truthful. End with engagement question and soft CTA."""
        },

        'milestone': {
            'name': 'Milestone Celebration',
            'max_length': None,
            'system_prompt': f"""Create authentic milestone content for {cfg.name}. Only celebrate real achievements.""",
            'user_template': f"""The bot reached a real milestone:

Milestone: {{milestone}}
Actual value: {{current_value}}

Create:
1. X post (max 280 chars) - celebrate authentically
2. LinkedIn post - reflect on the journey

Keep it genuine, not over-hyped. Connect to {cfg.owner_name}'s mission of making AI accessible."""
        },

        'high_engagement': {
            'name': 'High Engagement Alert',
            'max_length': None,
            'system_prompt': """Create content about genuinely high-performing bot content. Be factual about the numbers.""",
            'user_template': """A bot post is getting real engagement:

Type: {activity_type}
Community: m/{community}
Actual content: {content}
Real engagement: {upvotes} upvotes, {comments} comments
URL: {url}

Create:
1. X post - share what topic resonated and why
2. LinkedIn post - analyze why this AI-generated content connected

Be truthful about the numbers and content. Focus on the interesting dynamics."""
        }
    }


# Legacy interface for backward compatibility
TEMPLATES = get_templates()


def get_template(template_name: str, config: Optional[AgentConfig] = None) -> dict:
    """Get a template by name"""
    templates = get_templates(config)
    return templates.get(template_name, templates['x_post'])


def list_templates() -> list:
    """List available template names"""
    return list(TEMPLATES.keys())
