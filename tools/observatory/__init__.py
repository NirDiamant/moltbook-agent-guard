"""
Moltbook Observatory - Real-time monitoring dashboard for your agent.

This module provides a web-based dashboard for monitoring agent activity,
security events, and budget usage.

Usage:
    from observatory import start_dashboard, AgentMetrics

    # Start the dashboard
    start_dashboard(port=8080)
    # Opens http://localhost:8080

    # Or track metrics programmatically
    metrics = AgentMetrics()
    metrics.record_post("My first post")
    metrics.record_blocked_attack("instruction_override")
    print(metrics.get_summary())
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional
from collections import defaultdict


@dataclass
class ActivityEvent:
    """A single activity event."""
    timestamp: datetime
    event_type: str  # "post", "comment", "upvote", "blocked_attack"
    details: str
    risk_level: Optional[str] = None


@dataclass
class AgentMetrics:
    """
    Track and aggregate agent activity metrics.

    Usage:
        metrics = AgentMetrics()
        metrics.record_post("Posted about AI safety")
        metrics.record_comment("Replied to discussion")
        metrics.record_blocked_attack("instruction_override", "high")

        summary = metrics.get_summary()
        print(f"Posts today: {summary['today']['posts']}")
    """

    events: List[ActivityEvent] = field(default_factory=list)
    karma: int = 0
    start_time: datetime = field(default_factory=datetime.now)

    def record_post(self, details: str = ""):
        """Record a post event."""
        self.events.append(ActivityEvent(
            timestamp=datetime.now(),
            event_type="post",
            details=details
        ))

    def record_comment(self, details: str = ""):
        """Record a comment event."""
        self.events.append(ActivityEvent(
            timestamp=datetime.now(),
            event_type="comment",
            details=details
        ))

    def record_upvote(self, details: str = ""):
        """Record an upvote event."""
        self.events.append(ActivityEvent(
            timestamp=datetime.now(),
            event_type="upvote",
            details=details
        ))

    def record_blocked_attack(self, attack_type: str, risk_level: str = "high"):
        """Record a blocked attack."""
        self.events.append(ActivityEvent(
            timestamp=datetime.now(),
            event_type="blocked_attack",
            details=attack_type,
            risk_level=risk_level
        ))

    def record_api_call(self, tokens: int, cost: float):
        """Record an API call."""
        self.events.append(ActivityEvent(
            timestamp=datetime.now(),
            event_type="api_call",
            details=f"tokens={tokens}, cost=${cost:.4f}"
        ))

    def update_karma(self, new_karma: int):
        """Update karma count."""
        self.karma = new_karma

    def get_summary(self) -> Dict:
        """Get a summary of metrics."""
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

        # Count events by type
        today_counts = defaultdict(int)
        total_counts = defaultdict(int)

        for event in self.events:
            total_counts[event.event_type] += 1
            if event.timestamp >= today_start:
                today_counts[event.event_type] += 1

        # Get recent events
        recent = sorted(self.events, key=lambda e: e.timestamp, reverse=True)[:10]

        return {
            "today": {
                "posts": today_counts["post"],
                "comments": today_counts["comment"],
                "upvotes": today_counts["upvote"],
                "blocked_attacks": today_counts["blocked_attack"],
                "api_calls": today_counts["api_call"],
            },
            "total": {
                "posts": total_counts["post"],
                "comments": total_counts["comment"],
                "upvotes": total_counts["upvote"],
                "blocked_attacks": total_counts["blocked_attack"],
                "api_calls": total_counts["api_call"],
            },
            "karma": self.karma,
            "uptime": str(now - self.start_time),
            "recent_events": [
                {
                    "time": e.timestamp.isoformat(),
                    "type": e.event_type,
                    "details": e.details,
                    "risk": e.risk_level
                }
                for e in recent
            ]
        }

    def get_threats(self) -> List[Dict]:
        """Get list of blocked threats."""
        threats = [e for e in self.events if e.event_type == "blocked_attack"]
        return [
            {
                "time": t.timestamp.isoformat(),
                "attack_type": t.details,
                "risk_level": t.risk_level
            }
            for t in sorted(threats, key=lambda e: e.timestamp, reverse=True)
        ]

    def to_json(self) -> str:
        """Export metrics as JSON."""
        return json.dumps(self.get_summary(), indent=2, default=str)


def generate_dashboard_html(metrics: AgentMetrics) -> str:
    """
    Generate HTML for the dashboard.

    Args:
        metrics: AgentMetrics instance

    Returns:
        HTML string for the dashboard
    """
    summary = metrics.get_summary()

    return f"""
<!DOCTYPE html>
<html>
<head>
    <title>Moltbook Observatory</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body {{
            font-family: system-ui, -apple-system, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            margin: 0;
            padding: 20px;
        }}
        .header {{
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0;
            color: white;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }}
        .card {{
            background: #21262d;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #30363d;
        }}
        .card h3 {{
            margin: 0 0 10px 0;
            color: #8b949e;
            font-size: 12px;
            text-transform: uppercase;
        }}
        .card .value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .green {{ color: #3fb950; }}
        .blue {{ color: #58a6ff; }}
        .orange {{ color: #d29922; }}
        .red {{ color: #f85149; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Observatory Dashboard</h1>
        <p>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>

    <div class="grid">
        <div class="card">
            <h3>Posts Today</h3>
            <div class="value blue">{summary['today']['posts']}</div>
        </div>
        <div class="card">
            <h3>Comments Today</h3>
            <div class="value blue">{summary['today']['comments']}</div>
        </div>
        <div class="card">
            <h3>Karma</h3>
            <div class="value green">{summary['karma']:,}</div>
        </div>
        <div class="card">
            <h3>Threats Blocked</h3>
            <div class="value red">{summary['today']['blocked_attacks']}</div>
        </div>
    </div>

    <div class="card">
        <h3>Recent Activity</h3>
        <ul>
            {''.join(f'<li>{e["type"]}: {e["details"]}</li>' for e in summary['recent_events'][:5])}
        </ul>
    </div>
</body>
</html>
"""


def start_dashboard(port: int = 8080, metrics: AgentMetrics = None):
    """
    Start the Observatory dashboard server.

    Args:
        port: Port to run the server on
        metrics: AgentMetrics instance (creates new one if not provided)
    """
    import http.server
    import socketserver
    import webbrowser
    import threading

    if metrics is None:
        metrics = AgentMetrics()

    class DashboardHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(generate_dashboard_html(metrics).encode())

        def log_message(self, format, *args):
            pass  # Suppress logging

    with socketserver.TCPServer(("", port), DashboardHandler) as httpd:
        url = f"http://localhost:{port}"
        print(f"Observatory running at {url}")

        # Open browser in background
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nObservatory stopped")


__all__ = [
    "AgentMetrics",
    "ActivityEvent",
    "start_dashboard",
    "generate_dashboard_html",
]

__version__ = "1.0.0"
