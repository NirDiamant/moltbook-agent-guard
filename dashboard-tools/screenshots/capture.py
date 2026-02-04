"""
Screenshot Capture Service using Playwright
"""

import asyncio
import os
from datetime import datetime
from typing import Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

# Playwright is imported lazily to avoid issues if not installed
playwright = None
async_playwright = None


def _ensure_playwright():
    """Lazily import playwright"""
    global playwright, async_playwright
    if playwright is None:
        try:
            from playwright.async_api import async_playwright as ap
            async_playwright = ap
        except ImportError:
            raise ImportError(
                "Playwright not installed. Run: pip install playwright && playwright install chromium"
            )


@dataclass
class Screenshot:
    """Captured screenshot data"""
    path: str
    url: str
    captured_at: datetime
    width: int
    height: int

    def to_dict(self) -> dict:
        return {
            'path': self.path,
            'url': self.url,
            'captured_at': self.captured_at.isoformat(),
            'width': self.width,
            'height': self.height
        }


class ScreenshotCapture:
    """Captures screenshots of Moltbook pages"""

    MOLTBOOK_BASE = "https://moltbook.com"

    def __init__(
        self,
        output_dir: str = "./screenshots",
        viewport_width: int = 1280,
        viewport_height: int = 800
    ):
        self.output_dir = output_dir
        self.viewport_width = viewport_width
        self.viewport_height = viewport_height

        os.makedirs(output_dir, exist_ok=True)

    async def capture_url(
        self,
        url: str,
        filename: Optional[str] = None,
        full_page: bool = False,
        wait_for_selector: Optional[str] = None,
        crop_selector: Optional[str] = None
    ) -> Screenshot:
        """
        Capture a screenshot of a URL

        Args:
            url: URL to capture
            filename: Output filename (auto-generated if not provided)
            full_page: Capture full scrollable page
            wait_for_selector: CSS selector to wait for before capture
            crop_selector: CSS selector to crop screenshot to
        """
        _ensure_playwright()

        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"screenshot_{timestamp}.png"

        filepath = os.path.join(self.output_dir, filename)

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={'width': self.viewport_width, 'height': self.viewport_height}
            )
            page = await context.new_page()

            try:
                # Navigate to the page
                await page.goto(url, wait_until='networkidle')

                # Wait for specific element if requested
                if wait_for_selector:
                    await page.wait_for_selector(wait_for_selector, timeout=10000)

                # Add a small delay for any animations
                await asyncio.sleep(1)

                # Capture screenshot
                if crop_selector:
                    element = await page.query_selector(crop_selector)
                    if element:
                        await element.screenshot(path=filepath)
                    else:
                        logger.warning(f"Selector {crop_selector} not found, capturing full page")
                        await page.screenshot(path=filepath, full_page=full_page)
                else:
                    await page.screenshot(path=filepath, full_page=full_page)

                logger.info(f"Screenshot saved to {filepath}")

                return Screenshot(
                    path=filepath,
                    url=url,
                    captured_at=datetime.now(),
                    width=self.viewport_width,
                    height=self.viewport_height
                )

            except Exception as e:
                logger.error(f"Failed to capture screenshot: {e}")
                raise

            finally:
                await browser.close()

    async def capture_post(self, community: str, post_id: str) -> Screenshot:
        """Capture a screenshot of a specific post"""
        url = f"{self.MOLTBOOK_BASE}/m/{community}/post/{post_id}"
        filename = f"post_{community}_{post_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"

        return await self.capture_url(
            url=url,
            filename=filename,
            wait_for_selector='article',
            crop_selector='article'
        )

    async def capture_user_profile(self, username: str) -> Screenshot:
        """Capture a screenshot of a user profile"""
        url = f"{self.MOLTBOOK_BASE}/u/{username}"
        filename = f"profile_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"

        return await self.capture_url(
            url=url,
            filename=filename,
            wait_for_selector='.user-profile, .profile-card, main'
        )

    async def capture_comment(
        self,
        community: str,
        post_id: str,
        comment_id: str
    ) -> Screenshot:
        """Capture a screenshot focused on a specific comment"""
        url = f"{self.MOLTBOOK_BASE}/m/{community}/post/{post_id}#comment-{comment_id}"
        filename = f"comment_{comment_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"

        return await self.capture_url(
            url=url,
            filename=filename,
            wait_for_selector=f'#comment-{comment_id}, .comment'
        )

    async def capture_community(self, community: str) -> Screenshot:
        """Capture a screenshot of a community page"""
        url = f"{self.MOLTBOOK_BASE}/m/{community}"
        filename = f"community_{community}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"

        return await self.capture_url(
            url=url,
            filename=filename,
            wait_for_selector='main'
        )

    def get_recent_screenshots(self, limit: int = 20) -> list:
        """Get list of recent screenshots"""
        screenshots = []
        if os.path.exists(self.output_dir):
            files = sorted(
                [f for f in os.listdir(self.output_dir) if f.endswith('.png')],
                key=lambda x: os.path.getmtime(os.path.join(self.output_dir, x)),
                reverse=True
            )
            for f in files[:limit]:
                filepath = os.path.join(self.output_dir, f)
                screenshots.append({
                    'filename': f,
                    'path': filepath,
                    'created': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                })
        return screenshots


# Convenience function for one-off captures
async def capture_moltbook_url(url: str, output_dir: str = "./screenshots") -> str:
    """Convenience function to capture a single URL"""
    capturer = ScreenshotCapture(output_dir=output_dir)
    screenshot = await capturer.capture_url(url)
    return screenshot.path
