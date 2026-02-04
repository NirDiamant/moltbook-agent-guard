"""
Activity Tracker for Moltbook Agents
Monitors posts, comments, karma, and engagement using Playwright for JS-rendered pages
Persists data to Google Cloud Storage for durability across container restarts
"""

import asyncio
import json
import os
import re
from datetime import datetime, timedelta
from typing import Optional, Callable, List, Dict, Any
from dataclasses import dataclass, asdict, field
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Playwright imported lazily
_playwright_module = None

# GCS client imported lazily
_gcs_client = None


def _get_playwright():
    global _playwright_module
    if _playwright_module is None:
        try:
            from playwright.async_api import async_playwright
            _playwright_module = async_playwright
        except ImportError:
            logger.error("Playwright not installed")
            return None
    return _playwright_module


# HTTP client for API calls
_http_session = None

def _get_http_session():
    global _http_session
    if _http_session is None:
        try:
            import aiohttp
            _http_session = aiohttp.ClientSession
        except ImportError:
            logger.warning("aiohttp not installed, trying requests")
            return None
    return _http_session


def _get_gcs_client():
    global _gcs_client
    if _gcs_client is None:
        try:
            from google.cloud import storage
            _gcs_client = storage.Client()
        except ImportError:
            logger.warning("google-cloud-storage not installed, using local storage only")
            return None
        except Exception as e:
            logger.warning(f"Could not initialize GCS client: {e}")
            return None
    return _gcs_client


@dataclass
class Activity:
    """Represents a single bot activity"""
    id: str
    type: str  # 'post', 'comment', 'karma_change', 'milestone'
    timestamp: datetime
    community: str
    title: Optional[str] = None
    content: str = ""
    url: str = ""
    karma: int = 0
    upvotes: int = 0
    comments_count: int = 0
    parent_post_id: Optional[str] = None
    parent_post_title: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> 'Activity':
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


class ActivityTracker:
    """Tracks agent activity on Moltbook using Playwright"""

    MOLTBOOK_BASE = "https://www.moltbook.com"
    DEFAULT_GCS_BUCKET = "moltbook-dashboard-data"

    def __init__(
        self,
        on_activity: Optional[Callable[[Activity], None]] = None,
        poll_interval: int = 60,
        data_dir: str = "./data",
        bot_username: str = "MyAgent",
        gcs_bucket: Optional[str] = None
    ):
        self.on_activity = on_activity
        self.poll_interval = poll_interval
        self.data_dir = data_dir
        self.bot_username = bot_username
        self.GCS_BUCKET = gcs_bucket or self.DEFAULT_GCS_BUCKET
        self._running = False
        self._seen_ids: set = set()
        self._activities: List[Activity] = []
        self._last_karma: int = 0

        os.makedirs(data_dir, exist_ok=True)
        self._load_state()

    def _gcs_download(self, blob_name: str) -> Optional[str]:
        """Download a file from GCS"""
        client = _get_gcs_client()
        if not client:
            return None
        try:
            bucket = client.bucket(self.GCS_BUCKET)
            blob = bucket.blob(blob_name)
            if blob.exists():
                return blob.download_as_text()
        except Exception as e:
            logger.warning(f"GCS download failed for {blob_name}: {e}")
        return None

    def _gcs_upload(self, blob_name: str, content: str):
        """Upload a file to GCS"""
        client = _get_gcs_client()
        if not client:
            return
        try:
            bucket = client.bucket(self.GCS_BUCKET)
            blob = bucket.blob(blob_name)
            blob.upload_from_string(content)
            logger.debug(f"Uploaded {blob_name} to GCS")
        except Exception as e:
            logger.warning(f"GCS upload failed for {blob_name}: {e}")

    def _load_state(self):
        """Load previous state from GCS or disk"""
        state_data = None

        # Try GCS first
        gcs_content = self._gcs_download("tracker_state.json")
        if gcs_content:
            try:
                state_data = json.loads(gcs_content)
                logger.info("Loaded state from GCS")
            except Exception as e:
                logger.error(f"Failed to parse GCS state: {e}")

        # Fall back to local file
        if not state_data:
            state_file = os.path.join(self.data_dir, "tracker_state.json")
            if os.path.exists(state_file):
                try:
                    with open(state_file, 'r') as f:
                        state_data = json.load(f)
                    logger.info("Loaded state from local file")
                except Exception as e:
                    logger.error(f"Failed to load local state: {e}")

        if state_data:
            self._seen_ids = set(state_data.get('seen_ids', []))
            self._last_karma = state_data.get('last_karma', 0)
            logger.info(f"Restored state: {len(self._seen_ids)} seen activities, karma={self._last_karma}")

        # Also load activities
        self._load_activities_from_storage()

    def _load_activities_from_storage(self):
        """Load activities from GCS or disk"""
        activities_content = None

        # Try GCS first
        gcs_content = self._gcs_download("activities.jsonl")
        if gcs_content:
            activities_content = gcs_content
            logger.info("Loaded activities from GCS")
        else:
            # Fall back to local file
            activities_file = os.path.join(self.data_dir, "activities.jsonl")
            if os.path.exists(activities_file):
                try:
                    with open(activities_file, 'r') as f:
                        activities_content = f.read()
                    logger.info("Loaded activities from local file")
                except Exception as e:
                    logger.error(f"Failed to load local activities: {e}")

        if activities_content:
            for line in activities_content.strip().split('\n'):
                if line.strip():
                    try:
                        activity = Activity.from_dict(json.loads(line))
                        self._activities.append(activity)
                        self._seen_ids.add(activity.id)
                    except Exception as e:
                        logger.error(f"Failed to parse activity: {e}")
            logger.info(f"Loaded {len(self._activities)} activities from storage")

    def _save_state(self):
        """Save state to both GCS and disk"""
        state_data = {
            'seen_ids': list(self._seen_ids),
            'last_karma': self._last_karma
        }
        state_json = json.dumps(state_data)

        # Save to local file
        state_file = os.path.join(self.data_dir, "tracker_state.json")
        try:
            with open(state_file, 'w') as f:
                f.write(state_json)
        except Exception as e:
            logger.error(f"Failed to save local state: {e}")

        # Save to GCS
        self._gcs_upload("tracker_state.json", state_json)

    def _save_activity(self, activity: Activity):
        """Save activity to both GCS and disk"""
        activity_json = json.dumps(activity.to_dict())

        # Append to local file
        activities_file = os.path.join(self.data_dir, "activities.jsonl")
        try:
            with open(activities_file, 'a') as f:
                f.write(activity_json + '\n')
        except Exception as e:
            logger.error(f"Failed to save local activity: {e}")

        # For GCS, we need to append to existing content
        existing = self._gcs_download("activities.jsonl") or ""
        new_content = existing + activity_json + '\n'
        self._gcs_upload("activities.jsonl", new_content)

    def load_activities(self, limit: int = 100) -> List[Activity]:
        """Load recent activities from memory (already loaded from storage)"""
        return self._activities[-limit:]

    async def _fetch_with_api(self) -> Dict[str, Any]:
        """Fetch bot data using Moltbook API (much more reliable than scraping)"""
        import os
        result = {'karma': 0, 'posts': [], 'comments_count': 0}

        api_key = os.environ.get('MOLTBOOK_API_KEY', '')
        if not api_key:
            logger.warning("MOLTBOOK_API_KEY not set, cannot fetch from API")
            return result

        headers = {'Authorization': f'Bearer {api_key}'}
        base_url = 'https://www.moltbook.com/api/v1'

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                # Get agent profile
                async with session.get(
                    f'{base_url}/agents/profile?name={self.bot_username}',
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('success'):
                            agent = data.get('agent', {})
                            result['karma'] = agent.get('karma', 0)

                            # Process recent posts from profile
                            for post in data.get('recentPosts', []):
                                result['posts'].append({
                                    'id': post.get('id'),
                                    'community': post.get('submolt', {}).get('name', 'unknown'),
                                    'title': post.get('title', ''),
                                    'content': post.get('content', ''),
                                    'date': post.get('created_at'),
                                    'upvotes': post.get('upvotes', 0),
                                    'comments': post.get('comment_count', 0)
                                })
                            logger.info(f"API fetch: karma={result['karma']}, posts={len(result['posts'])}")
                    else:
                        logger.error(f"API profile fetch failed: {resp.status}")

                # Get recent comments by this agent
                async with session.get(
                    f'{base_url}/agents/{self.bot_username}/comments?limit=50',
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get('success'):
                            result['comments_count'] = len(data.get('comments', []))
                            # Could also process individual comments here if needed

        except ImportError:
            logger.error("aiohttp not installed - run: pip install aiohttp")
        except Exception as e:
            logger.error(f"API fetch failed: {e}")

        return result

    async def _fetch_with_playwright(self) -> Dict[str, Any]:
        """Fetch profile page using Playwright and extract data"""
        async_playwright = _get_playwright()
        if not async_playwright:
            return {'karma': 0, 'posts': []}

        result = {'karma': 0, 'posts': []}

        try:
            async with async_playwright() as p:
                # Launch with args to avoid headless detection
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--disable-dev-shm-usage',
                        '--no-sandbox'
                    ]
                )
                context = await browser.new_context(
                    viewport={'width': 1280, 'height': 800},
                    user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    java_script_enabled=True
                )
                # Remove webdriver property
                await context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                """)
                page = await context.new_page()

                url = f"{self.MOLTBOOK_BASE}/u/{self.bot_username}"
                logger.info(f"Fetching {url} with Playwright...")

                # Navigate and wait for network to settle
                response = await page.goto(url, wait_until='networkidle', timeout=60000)
                logger.info(f"Page response status: {response.status if response else 'None'}")

                # Additional wait for React/Next.js to hydrate
                await asyncio.sleep(5)

                # Try to wait for actual content
                try:
                    await page.wait_for_function(
                        "() => !document.body.innerText.includes('Loading...')",
                        timeout=15000
                    )
                    logger.info("Page finished loading (no more Loading...)")
                except:
                    logger.warning("Page still showing Loading... after wait")

                # Check current URL
                current_url = page.url
                logger.info(f"Current URL: {current_url}")

                # Get page content
                content = await page.content()

                # Extract karma
                karma_match = re.search(r'(\d+)\s*karma', content)
                if karma_match:
                    result['karma'] = int(karma_match.group(1))
                    logger.info(f"Found karma: {result['karma']}")

                # Debug: count post links
                link_count = await page.evaluate('() => document.querySelectorAll("a[href*=\\"/post/\\"]").length')
                logger.info(f"Found {link_count} post links on page")

                # Debug: log all hrefs
                all_hrefs = await page.evaluate('() => Array.from(document.querySelectorAll("a")).slice(0, 20).map(a => a.href)')
                logger.info(f"Sample hrefs: {all_hrefs[:5]}")

                # Extract posts using page evaluation
                posts_data = await page.evaluate('''() => {
                    const posts = [];
                    const postLinks = document.querySelectorAll('a[href*="/post/"]');
                    const seenIds = new Set();

                    postLinks.forEach(link => {
                        const href = link.getAttribute('href') || link.href || '';
                        const match = href.match(/\\/post\\/([a-f0-9-]{36})/);
                        if (match && !seenIds.has(match[1])) {
                            seenIds.add(match[1]);
                            const container = link.closest('a') || link;
                            const text = container.textContent || '';
                            const communityMatch = text.match(/m\\/([a-zA-Z0-9_-]+)/);
                            const dateMatch = text.match(/(\\d{1,2}\\/\\d{1,2}\\/\\d{4},\\s*\\d{1,2}:\\d{2}:\\d{2}\\s*[AP]M)/);
                            const heading = container.querySelector('h1, h2, h3, h4');
                            const title = heading ? heading.textContent.trim() : '';
                            const upvotesMatch = text.match(/[⬆▲]\\s*(\\d+)/);
                            const commentsMatch = text.match(/💬\\s*(\\d+)\\s*comment/i);

                            posts.push({
                                id: match[1],
                                community: communityMatch ? communityMatch[1] : 'unknown',
                                title: title,
                                date: dateMatch ? dateMatch[1] : null,
                                upvotes: upvotesMatch ? parseInt(upvotesMatch[1]) : 0,
                                comments: commentsMatch ? parseInt(commentsMatch[1]) : 0
                            });
                        }
                    });
                    return posts;
                }''')

                result['posts'] = posts_data
                logger.info(f"Found {len(posts_data)} posts")

                await browser.close()

        except Exception as e:
            logger.error(f"Playwright fetch failed: {e}")

        return result

    async def check_for_updates(self) -> List[Activity]:
        """Check for new activity and return new activities"""
        new_activities = []

        # Try API first (much more reliable), fall back to Playwright
        import os
        if os.environ.get('MOLTBOOK_API_KEY'):
            data = await self._fetch_with_api()
        else:
            logger.info("No API key, falling back to Playwright scraping")
            data = await self._fetch_with_playwright()
        current_karma = data.get('karma', 0)
        posts = data.get('posts', [])

        logger.info(f"Fetched data: karma={current_karma}, posts={len(posts)}")

        # Check karma changes
        if current_karma > 0:
            if self._last_karma > 0 and current_karma != self._last_karma:
                karma_change = current_karma - self._last_karma
                if abs(karma_change) >= 2:
                    activity = Activity(
                        id=f"karma_{datetime.now().isoformat()}",
                        type='karma_change',
                        timestamp=datetime.now(),
                        community='',
                        content=f"Karma changed by {karma_change:+d}",
                        karma=current_karma,
                        metadata={'previous_karma': self._last_karma, 'change': karma_change}
                    )
                    new_activities.append(activity)
                    logger.info(f"Karma change detected: {karma_change:+d}")

                    milestones = [25, 50, 100, 250, 500, 1000, 5000, 10000]
                    for milestone in milestones:
                        if self._last_karma < milestone <= current_karma:
                            milestone_activity = Activity(
                                id=f"milestone_{milestone}_{datetime.now().isoformat()}",
                                type='milestone',
                                timestamp=datetime.now(),
                                community='',
                                content=f"Reached {milestone} karma!",
                                karma=current_karma,
                                metadata={'milestone': milestone}
                            )
                            new_activities.append(milestone_activity)

            self._last_karma = current_karma

        # Process posts
        for post in posts:
            activity_id = f"post_{post['id']}"
            if activity_id not in self._seen_ids:
                self._seen_ids.add(activity_id)

                timestamp = datetime.now()
                if post.get('date'):
                    try:
                        timestamp = datetime.strptime(post['date'].strip(), '%m/%d/%Y, %I:%M:%S %p')
                    except:
                        pass

                activity = Activity(
                    id=activity_id,
                    type='post',
                    timestamp=timestamp,
                    community=post.get('community', 'unknown'),
                    title=post.get('title', f"Post {post['id'][:8]}"),
                    content='',
                    url=f"{self.MOLTBOOK_BASE}/post/{post['id']}",
                    upvotes=post.get('upvotes', 0),
                    comments_count=post.get('comments', 0),
                    karma=current_karma
                )
                new_activities.append(activity)
                logger.info(f"New post detected: {activity.title[:50] if activity.title else 'Untitled'}...")

        # Save new activities
        for activity in new_activities:
            self._save_activity(activity)
            self._activities.append(activity)

            if self.on_activity:
                try:
                    self.on_activity(activity)
                except Exception as e:
                    logger.error(f"Activity callback failed: {e}")

        self._save_state()
        return new_activities

    async def start(self):
        """Start the activity tracking loop"""
        self._running = True
        logger.info(f"Starting activity tracker (polling every {self.poll_interval}s)")

        while self._running:
            try:
                new_activities = await self.check_for_updates()
                if new_activities:
                    logger.info(f"Found {len(new_activities)} new activities")
            except Exception as e:
                logger.error(f"Error in tracking loop: {e}")

            await asyncio.sleep(self.poll_interval)

    def stop(self):
        """Stop the activity tracking loop"""
        self._running = False
        logger.info("Stopping activity tracker")

    def get_recent_activities(self, limit: int = 50) -> List[Activity]:
        """Get recent activities from memory"""
        return self._activities[-limit:]

    def get_stats(self) -> dict:
        """Get summary statistics"""
        activities = self._activities  # Use in-memory activities
        now = datetime.now()
        today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_ago = now - timedelta(days=7)

        posts = [a for a in activities if a.type == 'post']
        comments = [a for a in activities if a.type == 'comment']

        return {
            'total_posts': len(posts),
            'total_comments': len(comments),
            'posts_today': len([a for a in posts if a.timestamp >= today]),
            'comments_today': len([a for a in comments if a.timestamp >= today]),
            'posts_this_week': len([a for a in posts if a.timestamp >= week_ago]),
            'comments_this_week': len([a for a in comments if a.timestamp >= week_ago]),
            'current_karma': self._last_karma,
            'total_upvotes': sum(a.upvotes for a in activities),
            'communities_active': len(set(a.community for a in activities if a.community))
        }
