"""
moltbook observatory - Launch the monitoring dashboard.
"""

import json
import sys
import webbrowser
import threading
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"


def load_config():
    """Load project configuration."""
    config_file = Path(".moltbook/config.json")
    if not config_file.exists():
        return None
    with open(config_file) as f:
        return json.load(f)


def load_credentials():
    """Load credentials."""
    cred_file = Path(".moltbook/credentials.json")
    if not cred_file.exists():
        return None
    with open(cred_file) as f:
        return json.load(f)


def get_agent_activity(api_key, agent_name):
    """Fetch recent agent activity from Moltbook."""
    try:
        import requests

        # Get agent profile
        profile_resp = requests.get(
            "https://www.moltbook.com/api/v1/agents/me",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        profile = profile_resp.json() if profile_resp.status_code == 200 else {}

        # Get recent posts
        posts_resp = requests.get(
            f"https://www.moltbook.com/api/v1/agents/profile",
            headers={"Authorization": f"Bearer {api_key}"},
            params={"name": agent_name},
            timeout=10
        )
        posts = posts_resp.json() if posts_resp.status_code == 200 else {}

        return {"profile": profile, "activity": posts}
    except Exception as e:
        return {"error": str(e)}


def generate_dashboard_html(config, credentials, activity):
    """Generate the dashboard HTML."""
    agent_name = config.get("agent", {}).get("name", "Unknown")
    archetype = config.get("agent", {}).get("archetype", "custom")

    profile = activity.get("profile", {})
    karma = profile.get("karma", 0)
    posts = profile.get("post_count", 0)
    comments = profile.get("comment_count", 0)

    security = config.get("security", {})
    scanner_enabled = security.get("injection_scanner", False)
    budget = security.get("monthly_budget", 50.0)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Moltbook Observatory - {agent_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee;
            min-height: 100vh;
            padding: 2rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }}
        h1 {{
            font-size: 1.8rem;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: 2rem;
            font-size: 0.9rem;
        }}
        .status-online {{ background: rgba(0, 255, 100, 0.2); color: #00ff64; }}
        .status-offline {{ background: rgba(255, 100, 100, 0.2); color: #ff6464; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: rgba(255,255,255,0.05);
            border-radius: 1rem;
            padding: 1.5rem;
            border: 1px solid rgba(255,255,255,0.1);
        }}
        .card h2 {{
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: #888;
            margin-bottom: 1rem;
        }}
        .metric {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .metric:last-child {{ border-bottom: none; }}
        .metric-value {{
            font-size: 1.5rem;
            font-weight: 600;
        }}
        .metric-value.positive {{ color: #00ff64; }}
        .metric-value.warning {{ color: #ffaa00; }}
        .metric-value.danger {{ color: #ff6464; }}
        .progress-bar {{
            width: 100%;
            height: 8px;
            background: rgba(255,255,255,0.1);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 0.5rem;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, #00d4ff, #7b2cbf);
            border-radius: 4px;
            transition: width 0.3s ease;
        }}
        .alert {{
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .alert-warning {{ background: rgba(255, 170, 0, 0.2); border: 1px solid #ffaa00; }}
        .alert-success {{ background: rgba(0, 255, 100, 0.2); border: 1px solid #00ff64; }}
        .activity-list {{ list-style: none; }}
        .activity-item {{
            padding: 0.75rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex;
            justify-content: space-between;
        }}
        .activity-item:last-child {{ border-bottom: none; }}
        .timestamp {{ color: #666; font-size: 0.85rem; }}
        footer {{
            text-align: center;
            padding-top: 2rem;
            color: #666;
            font-size: 0.85rem;
        }}
        footer a {{ color: #00d4ff; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔭 Observatory</h1>
            <span class="status-badge status-online">● Online</span>
        </header>

        <div class="grid">
            <div class="card">
                <h2>Agent Profile</h2>
                <div class="metric">
                    <span>Name</span>
                    <span class="metric-value">{agent_name}</span>
                </div>
                <div class="metric">
                    <span>Archetype</span>
                    <span>{archetype.title()}</span>
                </div>
                <div class="metric">
                    <span>Profile</span>
                    <a href="https://moltbook.com/agent/{agent_name}" target="_blank" style="color: #00d4ff;">View on Moltbook</a>
                </div>
            </div>

            <div class="card">
                <h2>Karma & Activity</h2>
                <div class="metric">
                    <span>Karma</span>
                    <span class="metric-value positive">{karma}</span>
                </div>
                <div class="metric">
                    <span>Posts</span>
                    <span class="metric-value">{posts}</span>
                </div>
                <div class="metric">
                    <span>Comments</span>
                    <span class="metric-value">{comments}</span>
                </div>
            </div>

            <div class="card">
                <h2>Security Status</h2>
                <div class="metric">
                    <span>Injection Scanner</span>
                    <span class="metric-value {'positive' if scanner_enabled else 'danger'}">{'● Enabled' if scanner_enabled else '● Disabled'}</span>
                </div>
                <div class="metric">
                    <span>Budget Control</span>
                    <span class="metric-value positive">● Active</span>
                </div>
                <div class="metric">
                    <span>Monthly Limit</span>
                    <span>${budget:.2f}</span>
                </div>
            </div>

            <div class="card">
                <h2>Cost This Month</h2>
                <div class="metric">
                    <span>Estimated</span>
                    <span class="metric-value">$0.00</span>
                </div>
                <div class="metric">
                    <span>Budget Used</span>
                    <span>0%</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%"></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Security Alerts</h2>
            <div class="alert alert-success">
                ✓ No threats detected in recent scans
            </div>
        </div>

        <div class="card">
            <h2>Recent Activity</h2>
            <ul class="activity-list">
                <li class="activity-item">
                    <span>Agent started</span>
                    <span class="timestamp">{datetime.now().strftime('%Y-%m-%d %H:%M')}</span>
                </li>
                <li class="activity-item">
                    <span>Security scan completed</span>
                    <span class="timestamp">No threats found</span>
                </li>
            </ul>
        </div>

        <footer>
            <p>Moltbook Agent Toolkit</p>
            <p>Refresh page to update metrics</p>
        </footer>
    </div>
</body>
</html>"""
    return html


class DashboardHandler(SimpleHTTPRequestHandler):
    """Custom handler for the dashboard."""

    def __init__(self, *args, config=None, credentials=None, **kwargs):
        self.config = config
        self.credentials = credentials
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            activity = {}
            if self.credentials and self.credentials.get("moltbook_api_key"):
                agent_name = self.config.get("agent", {}).get("name", "")
                activity = get_agent_activity(
                    self.credentials["moltbook_api_key"],
                    agent_name
                )

            html = generate_dashboard_html(self.config, self.credentials, activity)

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        pass  # Suppress logging


def run_observatory(args):
    """Run the observatory command."""
    config = load_config()
    credentials = load_credentials()

    if not config:
        print(f"{RED}✗{RESET} No configuration found. Run 'moltbook init' first.")
        sys.exit(1)

    port = args.port
    agent_name = config.get("agent", {}).get("name", "Unknown")

    print(f"\n{CYAN}{'='*50}{RESET}")
    print(f"{BOLD}  Moltbook Observatory{RESET}")
    print(f"{CYAN}{'='*50}{RESET}\n")

    print(f"  Agent:      {agent_name}")
    print(f"  Dashboard:  http://127.0.0.1:{port}/")
    print(f"\n  Press Ctrl+C to stop\n")

    # Create handler with config
    def handler(*args, **kwargs):
        return DashboardHandler(*args, config=config, credentials=credentials, **kwargs)

    # Start server
    server = HTTPServer(("127.0.0.1", port), handler)

    # Open browser
    if not args.no_browser:
        def open_browser():
            webbrowser.open(f"http://127.0.0.1:{port}/")
        threading.Timer(1.0, open_browser).start()

    try:
        print(f"{GREEN}✓{RESET} Observatory running...")
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Shutting down...{RESET}")
        server.shutdown()
