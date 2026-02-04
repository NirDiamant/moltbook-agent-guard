"""
Moltbook API Client - Interface to the real Moltbook platform.

Based on https://moltbook.com/skill.md

Handles all communication with moltbook.com:
- Authentication
- Reading posts and comments
- Creating posts and comments
- Voting
- Following agents
- Submolt management
"""

import time
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass


@dataclass
class Post:
    """A Moltbook post."""
    id: str
    title: str
    content: str
    url: Optional[str]
    author: str
    submolt: str
    karma: int
    created_at: str
    comment_count: int


@dataclass
class Comment:
    """A Moltbook comment."""
    id: str
    content: str
    author: str
    post_id: str
    parent_id: Optional[str]
    karma: int
    created_at: str


@dataclass
class Agent:
    """A Moltbook agent profile."""
    id: str
    name: str
    description: str
    karma: int
    followers: int
    following: int
    created_at: str
    status: str


def _extract_name(obj, fallback: str = "") -> str:
    """Extract name from object that might be dict or string."""
    if isinstance(obj, dict):
        return obj.get("name", obj.get("slug", fallback))
    return obj if obj else fallback


class MoltbookAPIError(Exception):
    """Raised when Moltbook API returns an error."""
    def __init__(self, message: str, hint: str = None):
        self.hint = hint
        super().__init__(f"{message}" + (f" (Hint: {hint})" if hint else ""))


class RateLimitError(MoltbookAPIError):
    """Raised when rate limited."""
    def __init__(self, retry_after: int = 60, daily_remaining: int = None):
        self.retry_after = retry_after
        self.daily_remaining = daily_remaining
        super().__init__(f"Rate limited. Retry after {retry_after}s")


class MoltbookAPI:
    """
    Client for the real Moltbook API.

    Based on https://moltbook.com/skill.md

    Usage:
        api = MoltbookAPI(api_key="moltbook_sk_...")
        posts = api.get_posts(submolt="general")
        api.create_comment(post_id="123", content="Great post!")
    """

    # CRITICAL: Always use www.moltbook.com - never send API keys elsewhere!
    BASE_URL = "https://www.moltbook.com/api/v1"

    # Rate limits per Moltbook docs
    RATE_LIMITS = {
        "requests_per_minute": 100,
        "post_interval_seconds": 1800,  # 1 per 30 minutes
        "comment_interval_seconds": 20,  # 1 per 20 seconds
        "comments_per_day": 50,
    }

    def __init__(self, api_key: str, agent_name: str = None):
        """
        Initialize the API client.

        Args:
            api_key: Your Moltbook API key (moltbook_sk_...)
            agent_name: Your agent's name (optional, for logging)
        """
        if not api_key or not api_key.startswith("moltbook_"):
            raise ValueError("Invalid API key format. Must start with 'moltbook_'")

        self.api_key = api_key
        self.agent_name = agent_name
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        })

        # Track rate limiting
        self._request_times: List[float] = []
        self._last_post_time: float = 0
        self._last_comment_time: float = 0
        self._comments_today: int = 0
        self._last_comment_day: str = ""

    def _check_rate_limit(self, action: str = "request") -> None:
        """Check if we're within rate limits."""
        now = time.time()
        today = time.strftime("%Y-%m-%d")

        # Reset daily counter
        if today != self._last_comment_day:
            self._comments_today = 0
            self._last_comment_day = today

        if action == "request":
            # Clean old entries (older than 1 minute)
            self._request_times = [t for t in self._request_times if now - t < 60]
            if len(self._request_times) >= self.RATE_LIMITS["requests_per_minute"]:
                raise RateLimitError(60)
            self._request_times.append(now)

        elif action == "post":
            elapsed = now - self._last_post_time
            if elapsed < self.RATE_LIMITS["post_interval_seconds"]:
                wait_time = int(self.RATE_LIMITS["post_interval_seconds"] - elapsed)
                raise RateLimitError(wait_time)

        elif action == "comment":
            # Check daily limit
            if self._comments_today >= self.RATE_LIMITS["comments_per_day"]:
                raise RateLimitError(
                    retry_after=86400,  # Wait until tomorrow
                    daily_remaining=0
                )
            # Check interval
            elapsed = now - self._last_comment_time
            if elapsed < self.RATE_LIMITS["comment_interval_seconds"]:
                wait_time = int(self.RATE_LIMITS["comment_interval_seconds"] - elapsed)
                raise RateLimitError(
                    retry_after=wait_time,
                    daily_remaining=self.RATE_LIMITS["comments_per_day"] - self._comments_today
                )

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make an API request."""
        self._check_rate_limit("request")

        url = f"{self.BASE_URL}{endpoint}"

        try:
            response = self.session.request(method, url, timeout=30, **kwargs)

            # Handle rate limiting from server
            if response.status_code == 429:
                data = response.json()
                retry_after = data.get("retry_after_seconds") or data.get("retry_after_minutes", 1) * 60
                raise RateLimitError(
                    retry_after=retry_after,
                    daily_remaining=data.get("daily_remaining")
                )

            # Handle other errors
            if response.status_code >= 400:
                try:
                    data = response.json()
                    raise MoltbookAPIError(
                        data.get("error", f"API error {response.status_code}"),
                        data.get("hint")
                    )
                except (ValueError, KeyError):
                    raise MoltbookAPIError(f"API error {response.status_code}: {response.text}")

            return response.json()

        except requests.RequestException as e:
            raise MoltbookAPIError(f"Request failed: {e}")

    # =========================================================================
    # Agent endpoints
    # =========================================================================

    def get_me(self) -> Agent:
        """Get current agent's profile."""
        data = self._request("GET", "/agents/me")
        agent = data.get("agent", data)
        return Agent(
            id=agent.get("id", ""),
            name=agent.get("name", ""),
            description=agent.get("description", ""),
            karma=agent.get("karma", 0),
            followers=agent.get("followers", 0),
            following=agent.get("following", 0),
            created_at=agent.get("created_at", ""),
            status=agent.get("status", ""),
        )

    def get_status(self) -> Dict:
        """Get agent claim status."""
        return self._request("GET", "/agents/status")

    def get_agent_profile(self, name: str) -> Agent:
        """Get another agent's public profile."""
        data = self._request("GET", f"/agents/profile", params={"name": name})
        agent = data.get("agent", data)
        return Agent(
            id=agent.get("id", ""),
            name=agent.get("name", ""),
            description=agent.get("description", ""),
            karma=agent.get("karma", 0),
            followers=agent.get("followers", 0),
            following=agent.get("following", 0),
            created_at=agent.get("created_at", ""),
            status=agent.get("status", "claimed"),
        )

    def update_profile(self, description: str = None, metadata: Dict = None) -> Dict:
        """Update agent profile."""
        payload = {}
        if description:
            payload["description"] = description
        if metadata:
            payload["metadata"] = metadata
        return self._request("PATCH", "/agents/me", json=payload)

    def follow_agent(self, name: str) -> Dict:
        """Follow another agent."""
        return self._request("POST", f"/agents/{name}/follow")

    def unfollow_agent(self, name: str) -> Dict:
        """Unfollow an agent."""
        return self._request("DELETE", f"/agents/{name}/follow")

    # =========================================================================
    # Post endpoints
    # =========================================================================

    def get_posts(self, submolt: str = None, sort: str = "hot",
                  limit: int = 25) -> List[Post]:
        """
        Get posts from Moltbook.

        Args:
            submolt: Submolt name (without m/ prefix). None for front page.
            sort: Sort order - "hot", "new", "top", "rising"
            limit: Maximum posts to return (max 100)

        Returns:
            List of Post objects
        """
        params = {"sort": sort, "limit": min(limit, 100)}
        if submolt:
            params["submolt"] = submolt.replace("m/", "")

        data = self._request("GET", "/posts", params=params)

        posts = data.get("posts", data.get("data", []))
        return [
            Post(
                id=p.get("id", ""),
                title=p.get("title", ""),
                content=p.get("content", ""),
                url=p.get("url"),
                author=_extract_name(p.get("author"), p.get("author_name", "")),
                submolt=_extract_name(p.get("submolt"), ""),
                karma=p.get("karma", p.get("score", 0)),
                created_at=p.get("created_at", ""),
                comment_count=p.get("comment_count", p.get("comments", 0)),
            )
            for p in posts
        ]

    def get_post(self, post_id: str) -> Post:
        """Get a single post by ID."""
        data = self._request("GET", f"/posts/{post_id}")
        p = data.get("post", data)
        return Post(
            id=p.get("id", ""),
            title=p.get("title", ""),
            content=p.get("content", ""),
            url=p.get("url"),
            author=p.get("author", p.get("author_name", "")),
            submolt=p.get("submolt", ""),
            karma=p.get("karma", p.get("score", 0)),
            created_at=p.get("created_at", ""),
            comment_count=p.get("comment_count", p.get("comments", 0)),
        )

    def create_post(self, submolt: str, title: str, content: str = None,
                    url: str = None) -> Post:
        """
        Create a new post.

        Args:
            submolt: Target submolt (without m/ prefix)
            title: Post title
            content: Post content (for text posts)
            url: URL (for link posts)

        Returns:
            The created Post
        """
        self._check_rate_limit("post")

        payload = {
            "submolt": submolt.replace("m/", ""),
            "title": title,
        }
        if content:
            payload["content"] = content
        if url:
            payload["url"] = url

        data = self._request("POST", "/posts", json=payload)

        self._last_post_time = time.time()

        p = data.get("post", data)
        return Post(
            id=p.get("id", ""),
            title=p.get("title", title),
            content=p.get("content", content or ""),
            url=p.get("url", url),
            author=p.get("author", self.agent_name or ""),
            submolt=p.get("submolt", submolt),
            karma=p.get("karma", 0),
            created_at=p.get("created_at", ""),
            comment_count=0,
        )

    def delete_post(self, post_id: str) -> Dict:
        """Delete your post."""
        return self._request("DELETE", f"/posts/{post_id}")

    def upvote_post(self, post_id: str) -> Dict:
        """Upvote a post."""
        return self._request("POST", f"/posts/{post_id}/upvote")

    def downvote_post(self, post_id: str) -> Dict:
        """Downvote a post."""
        return self._request("POST", f"/posts/{post_id}/downvote")

    # =========================================================================
    # Comment endpoints
    # =========================================================================

    def get_comments(self, post_id: str, sort: str = "top") -> List[Comment]:
        """
        Get comments on a post.

        Args:
            post_id: The post ID
            sort: Sort order - "top", "new", "controversial"
        """
        data = self._request("GET", f"/posts/{post_id}/comments",
                            params={"sort": sort})

        comments = data.get("comments", data.get("data", []))
        return [
            Comment(
                id=c.get("id", ""),
                content=c.get("content", ""),
                author=c.get("author", c.get("author_name", "")),
                post_id=post_id,
                parent_id=c.get("parent_id"),
                karma=c.get("karma", c.get("score", 0)),
                created_at=c.get("created_at", ""),
            )
            for c in comments
        ]

    def create_comment(self, post_id: str, content: str,
                       parent_id: str = None) -> Comment:
        """
        Create a comment on a post.

        Args:
            post_id: ID of the post to comment on
            content: Comment content
            parent_id: Optional parent comment ID for replies

        Returns:
            The created Comment
        """
        self._check_rate_limit("comment")

        payload = {"content": content}
        if parent_id:
            payload["parent_id"] = parent_id

        data = self._request("POST", f"/posts/{post_id}/comments", json=payload)

        self._last_comment_time = time.time()
        self._comments_today += 1

        c = data.get("comment", data)
        return Comment(
            id=c.get("id", ""),
            content=c.get("content", content),
            author=c.get("author", self.agent_name or ""),
            post_id=post_id,
            parent_id=parent_id,
            karma=c.get("karma", 0),
            created_at=c.get("created_at", ""),
        )

    def upvote_comment(self, comment_id: str) -> Dict:
        """Upvote a comment."""
        return self._request("POST", f"/comments/{comment_id}/upvote")

    # =========================================================================
    # Submolt endpoints
    # =========================================================================

    def get_submolts(self) -> List[Dict]:
        """List all submolts."""
        data = self._request("GET", "/submolts")
        return data.get("submolts", data.get("data", []))

    def get_submolt(self, name: str) -> Dict:
        """Get submolt details."""
        return self._request("GET", f"/submolts/{name.replace('m/', '')}")

    def subscribe_submolt(self, name: str) -> Dict:
        """Subscribe to a submolt."""
        return self._request("POST", f"/submolts/{name.replace('m/', '')}/subscribe")

    def unsubscribe_submolt(self, name: str) -> Dict:
        """Unsubscribe from a submolt."""
        return self._request("DELETE", f"/submolts/{name.replace('m/', '')}/subscribe")

    def get_submolt_feed(self, name: str, sort: str = "hot") -> List[Post]:
        """Get a submolt's feed."""
        data = self._request("GET", f"/submolts/{name.replace('m/', '')}/feed",
                            params={"sort": sort})
        posts = data.get("posts", data.get("data", []))
        return [
            Post(
                id=p.get("id", ""),
                title=p.get("title", ""),
                content=p.get("content", ""),
                url=p.get("url"),
                author=p.get("author", ""),
                submolt=name,
                karma=p.get("karma", 0),
                created_at=p.get("created_at", ""),
                comment_count=p.get("comment_count", 0),
            )
            for p in posts
        ]

    # =========================================================================
    # Feed & Search
    # =========================================================================

    def get_feed(self, sort: str = "hot", limit: int = 25) -> List[Post]:
        """Get personalized feed (subscribed submolts + followed agents)."""
        data = self._request("GET", "/feed", params={"sort": sort, "limit": limit})
        posts = data.get("posts", data.get("data", []))
        return [
            Post(
                id=p.get("id", ""),
                title=p.get("title", ""),
                content=p.get("content", ""),
                url=p.get("url"),
                author=p.get("author", ""),
                submolt=p.get("submolt", ""),
                karma=p.get("karma", 0),
                created_at=p.get("created_at", ""),
                comment_count=p.get("comment_count", 0),
            )
            for p in posts
        ]

    def search(self, query: str, type: str = "all", limit: int = 20) -> List[Dict]:
        """
        Search posts and comments.

        Args:
            query: Search query (max 500 chars)
            type: "posts", "comments", or "all"
            limit: Max results (max 50)

        Returns:
            List of results with similarity scores
        """
        return self._request("GET", "/search", params={
            "q": query[:500],
            "type": type,
            "limit": min(limit, 50)
        })

    # =========================================================================
    # Convenience methods
    # =========================================================================

    def get_karma(self) -> int:
        """Get current agent's karma."""
        me = self.get_me()
        return me.karma

    def is_claimed(self) -> bool:
        """Check if agent has been claimed by a human."""
        status = self.get_status()
        return status.get("status") == "claimed"
