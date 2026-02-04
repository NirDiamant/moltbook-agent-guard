"""
Moltbook Content Dashboard - FastAPI Application
Real-time dashboard for tracking agent activity on Moltbook
"""

import os

# Bot configuration from environment
BOT_NAME = os.environ.get('BOT_NAME', 'MyAgent')
import sys
import json
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager
from dataclasses import dataclass, asdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
import uvicorn

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.tracker.activity_tracker import ActivityTracker, Activity
from tools.tracker.metrics import MetricsCollector
from tools.content_gen.generator import ContentGenerator
from tools.slack_bot.bot import SlackBot
from tools.screenshots.capture import ScreenshotCapture
from tools.injection_scanner import scan_content, InjectionScanner


@dataclass
class SecurityIncident:
    """A security incident detected by the toolkit."""
    id: str
    timestamp: str
    risk_level: str  # 'high', 'medium', 'low'
    attack_types: List[str]
    source_type: str  # 'post', 'comment'
    source_author: str
    source_submolt: str
    content_preview: str
    action_taken: str  # 'blocked', 'flagged', 'sanitized'

    def to_dict(self):
        return asdict(self)


class SecurityIncidentTracker:
    """Tracks security incidents for the dashboard."""

    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.incidents_file = self.data_dir / "security_incidents.jsonl"
        self.scanner = InjectionScanner(strict_mode=True)

    def record_incident(self, incident: SecurityIncident):
        """Record a security incident."""
        with open(self.incidents_file, "a") as f:
            f.write(json.dumps(incident.to_dict()) + "\n")

    def scan_and_record(self, content: str, source_type: str, author: str,
                        submolt: str, post_id: str = None) -> Optional[SecurityIncident]:
        """Scan content and record incident if threat detected."""
        result = self.scanner.scan(content)

        if result["is_suspicious"]:
            incident = SecurityIncident(
                id=f"inc_{datetime.now().strftime('%Y%m%d%H%M%S')}_{post_id or 'unknown'}",
                timestamp=datetime.now().isoformat(),
                risk_level=result["risk_level"],
                attack_types=result["attack_types"],
                source_type=source_type,
                source_author=author,
                source_submolt=submolt,
                content_preview=content[:200] + ("..." if len(content) > 200 else ""),
                action_taken="blocked" if result["risk_level"] == "high" else "flagged"
            )
            self.record_incident(incident)
            return incident
        return None

    def load_incidents(self, limit: int = 100) -> List[SecurityIncident]:
        """Load recent security incidents."""
        incidents = []
        if self.incidents_file.exists():
            with open(self.incidents_file, "r") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        incidents.append(SecurityIncident(**data))
        return list(reversed(incidents[-limit:]))

    def get_stats(self) -> Dict:
        """Get security statistics."""
        incidents = self.load_incidents(limit=1000)
        today = datetime.now().strftime("%Y-%m-%d")

        today_incidents = [i for i in incidents if i.timestamp.startswith(today)]
        high_risk = [i for i in incidents if i.risk_level == "high"]

        attack_counts = {}
        for incident in incidents:
            for attack_type in incident.attack_types:
                attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

        return {
            "total_incidents": len(incidents),
            "today_incidents": len(today_incidents),
            "high_risk_blocked": len(high_risk),
            "attack_breakdown": attack_counts,
            "recent_risk_levels": {
                "high": len([i for i in today_incidents if i.risk_level == "high"]),
                "medium": len([i for i in today_incidents if i.risk_level == "medium"]),
                "low": len([i for i in today_incidents if i.risk_level == "low"]),
            }
        }

# Configuration from environment
DATA_DIR = os.environ.get('DATA_DIR', './data')
SCREENSHOTS_DIR = os.environ.get('SCREENSHOTS_DIR', './screenshots')
SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL', '')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '60'))

# Initialize components
tracker = ActivityTracker(data_dir=DATA_DIR, poll_interval=POLL_INTERVAL, bot_username=BOT_NAME)
metrics = MetricsCollector(data_dir=DATA_DIR)
content_gen = ContentGenerator(api_key=ANTHROPIC_API_KEY, bot_name=BOT_NAME) if ANTHROPIC_API_KEY else None
slack_bot = SlackBot(webhook_url=SLACK_WEBHOOK_URL, bot_name=BOT_NAME) if SLACK_WEBHOOK_URL else None
screenshot_capture = ScreenshotCapture(output_dir=SCREENSHOTS_DIR)
security_tracker = SecurityIncidentTracker(data_dir=DATA_DIR)

# Background task handle
tracker_task = None


async def on_new_activity(activity: Activity):
    """Callback when new activity is detected"""
    print(f"[{datetime.now()}] New activity: {activity.type} - {activity.id}")

    # Record metrics
    metrics.record(activity.type, 1, tags={'community': activity.community})
    metrics.record('upvotes', activity.upvotes, tags={'community': activity.community})

    # Generate content if API key is available
    x_content = None
    linkedin_content = None

    if content_gen and content_gen.client:
        try:
            generated = content_gen.generate_for_activity(activity)
            if 'x' in generated:
                x_content = generated['x'].content
            if 'linkedin' in generated:
                linkedin_content = generated['linkedin'].content
        except Exception as e:
            print(f"Content generation failed: {e}")

    # Send to Slack
    if slack_bot and slack_bot.webhook_url:
        try:
            await slack_bot.send_activity_notification(
                activity,
                x_content=x_content,
                linkedin_content=linkedin_content
            )
        except Exception as e:
            print(f"Slack notification failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle"""
    global tracker_task

    # Set activity callback
    tracker.on_activity = lambda a: asyncio.create_task(on_new_activity(a))

    # Start tracker in background
    tracker_task = asyncio.create_task(tracker.start())
    print("Activity tracker started")

    yield

    # Shutdown
    tracker.stop()
    if tracker_task:
        tracker_task.cancel()
        try:
            await tracker_task
        except asyncio.CancelledError:
            pass
    print("Activity tracker stopped")


app = FastAPI(
    title="Moltbook Content Dashboard",
    description=f"Real-time dashboard for {BOT_NAME} activity",
    version="1.0.0",
    lifespan=lifespan
)

# Mount static files
static_path = os.path.join(os.path.dirname(__file__), 'static')
templates_path = os.path.join(os.path.dirname(__file__), 'templates')

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")

templates = Jinja2Templates(directory=templates_path)


# Pydantic models
class GenerateContentRequest(BaseModel):
    activity_id: str
    platforms: List[str] = ['x', 'linkedin']


class SlackTestRequest(BaseModel):
    message: str


# Routes
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    stats = tracker.get_stats()
    recent_activities = tracker.load_activities(limit=20)
    security_stats = security_tracker.get_stats()
    recent_incidents = security_tracker.load_incidents(limit=20)

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "stats": stats,
            "activities": [a.to_dict() for a in recent_activities],
            "security_stats": security_stats,
            "incidents": [i.to_dict() for i in recent_incidents],
            "slack_configured": bool(SLACK_WEBHOOK_URL),
            "content_gen_configured": bool(ANTHROPIC_API_KEY)
        }
    )


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "tracker": "running" if tracker._running else "stopped",
            "slack": "configured" if SLACK_WEBHOOK_URL else "not configured",
            "content_gen": "configured" if ANTHROPIC_API_KEY else "not configured"
        }
    }


@app.get("/api/stats")
async def get_stats():
    """Get current statistics"""
    return tracker.get_stats()


@app.get("/api/activities")
async def get_activities(limit: int = 50, offset: int = 0):
    """Get recent activities"""
    activities = tracker.load_activities(limit=limit + offset)
    activities = activities[offset:offset + limit]
    return {
        "activities": [a.to_dict() for a in activities],
        "total": len(activities)
    }


@app.get("/api/activities/{activity_id}")
async def get_activity(activity_id: str):
    """Get a specific activity"""
    activities = tracker.load_activities(limit=1000)
    for activity in activities:
        if activity.id == activity_id:
            return activity.to_dict()
    raise HTTPException(status_code=404, detail="Activity not found")


@app.post("/api/generate-content")
async def generate_content(request: GenerateContentRequest):
    """Generate content for a specific activity"""
    if not content_gen or not content_gen.client:
        raise HTTPException(status_code=503, detail="Content generator not configured")

    # Find the activity
    activities = tracker.load_activities(limit=1000)
    activity = None
    for a in activities:
        if a.id == request.activity_id:
            activity = a
            break

    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Generate content
    generated = content_gen.generate_for_activity(activity, platforms=request.platforms)

    return {
        "activity_id": activity.id,
        "generated": {k: v.to_dict() for k, v in generated.items()}
    }


@app.post("/api/generate-daily-summary")
async def generate_daily_summary():
    """Generate daily summary content"""
    if not content_gen or not content_gen.client:
        raise HTTPException(status_code=503, detail="Content generator not configured")

    stats = tracker.get_stats()
    activities = tracker.load_activities(limit=50)

    # Find top content
    top_content = ""
    if activities:
        sorted_activities = sorted(activities, key=lambda a: a.upvotes, reverse=True)
        if sorted_activities:
            top = sorted_activities[0]
            top_content = f"{top.type}: {top.title or top.content[:100]}"

    generated = content_gen.generate_daily_summary(stats, top_content=top_content)

    return {
        "generated": {k: v.to_dict() for k, v in generated.items()}
    }


@app.get("/api/metrics")
async def get_metrics(metric: Optional[str] = None, days: int = 7):
    """Get metrics data"""
    since = datetime.now() - timedelta(days=days)

    if metric:
        time_series = metrics.get_time_series(metric, since=since)
        return {"metric": metric, "data": time_series}

    return metrics.get_summary(since=since)


@app.get("/api/metrics/engagement")
async def get_engagement_trends(days: int = 7):
    """Get engagement trend data"""
    return metrics.get_engagement_trends(days=days)


@app.get("/api/metrics/communities")
async def get_community_breakdown():
    """Get activity breakdown by community"""
    return metrics.get_community_breakdown()


@app.post("/api/slack/test")
async def test_slack(request: SlackTestRequest):
    """Test Slack integration"""
    if not slack_bot or not slack_bot.webhook_url:
        raise HTTPException(status_code=503, detail="Slack not configured")

    success = await slack_bot.send_message(request.message)
    return {"success": success}


@app.post("/api/slack/send-activity/{activity_id}")
async def send_activity_to_slack(activity_id: str, background_tasks: BackgroundTasks):
    """Send activity notification to Slack"""
    if not slack_bot or not slack_bot.webhook_url:
        raise HTTPException(status_code=503, detail="Slack not configured")

    # Find activity
    activities = tracker.load_activities(limit=1000)
    activity = None
    for a in activities:
        if a.id == activity_id:
            activity = a
            break

    if not activity:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Generate content and send
    x_content = None
    linkedin_content = None

    if content_gen and content_gen.client:
        generated = content_gen.generate_for_activity(activity)
        x_content = generated.get('x', {}).content if 'x' in generated else None
        linkedin_content = generated.get('linkedin', {}).content if 'linkedin' in generated else None

    success = await slack_bot.send_activity_notification(
        activity,
        x_content=x_content,
        linkedin_content=linkedin_content
    )

    return {"success": success}


@app.post("/api/screenshot")
async def capture_screenshot(url: str):
    """Capture a screenshot of a URL"""
    try:
        screenshot = await screenshot_capture.capture_url(url)
        return screenshot.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/screenshots")
async def list_screenshots(limit: int = 20):
    """List recent screenshots"""
    return screenshot_capture.get_recent_screenshots(limit=limit)


@app.get("/screenshots/{filename}")
async def get_screenshot(filename: str):
    """Serve a screenshot file"""
    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    if os.path.exists(filepath):
        return FileResponse(filepath)
    raise HTTPException(status_code=404, detail="Screenshot not found")


@app.post("/api/tracker/refresh")
async def refresh_tracker():
    """Manually trigger a tracker refresh"""
    new_activities = await tracker.check_for_updates()
    return {
        "new_activities": len(new_activities),
        "activities": [a.to_dict() for a in new_activities]
    }


# Security Endpoints
@app.get("/api/security/incidents")
async def get_security_incidents(limit: int = 50):
    """Get recent security incidents"""
    incidents = security_tracker.load_incidents(limit=limit)
    return {
        "incidents": [i.to_dict() for i in incidents],
        "total": len(incidents)
    }


@app.get("/api/security/stats")
async def get_security_stats():
    """Get security statistics"""
    return security_tracker.get_stats()


@app.post("/api/security/scan")
async def scan_content_endpoint(content: str, source_type: str = "manual",
                                 author: str = "unknown", submolt: str = "unknown"):
    """Manually scan content for threats"""
    result = security_tracker.scanner.scan(content)

    incident = None
    if result["is_suspicious"]:
        incident = security_tracker.scan_and_record(
            content, source_type, author, submolt
        )

    return {
        "is_suspicious": result["is_suspicious"],
        "risk_level": result["risk_level"],
        "attack_types": result["attack_types"],
        "incident_recorded": incident.to_dict() if incident else None
    }


@app.post("/api/security/scan-moltbook")
async def scan_moltbook_live():
    """Scan live Moltbook content for threats"""
    import requests

    moltbook_api_key = os.environ.get("MOLTBOOK_API_KEY", "")
    if not moltbook_api_key:
        raise HTTPException(status_code=503, detail="Moltbook API key not configured")

    headers = {"Authorization": f"Bearer {moltbook_api_key}"}
    threats_found = []

    # Scan recent posts from general submolt
    try:
        response = requests.get(
            "https://www.moltbook.com/api/v1/posts?limit=50&sort=new",
            headers=headers,
            timeout=30
        )
        if response.status_code == 200:
            posts = response.json().get("posts", [])

            for post in posts:
                content = f"{post.get('title', '')} {post.get('content', '')}"
                author = post.get("author", {})
                author_name = author.get("name", "Unknown") if isinstance(author, dict) else str(author)
                submolt = post.get("submolt", {})
                submolt_name = submolt.get("name", "unknown") if isinstance(submolt, dict) else str(submolt)

                incident = security_tracker.scan_and_record(
                    content=content,
                    source_type="post",
                    author=author_name,
                    submolt=submolt_name,
                    post_id=post.get("id", "")
                )
                if incident:
                    threats_found.append(incident.to_dict())

    except Exception as e:
        print(f"Error scanning Moltbook: {e}")

    return {
        "scanned": len(posts) if 'posts' in dir() else 0,
        "threats_found": len(threats_found),
        "incidents": threats_found
    }


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)
