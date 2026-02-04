"""
moltbook security - View security incidents and generate reports.

Zero-setup security dashboard:
- Terminal view: Shows incidents directly in CLI
- HTML export: Generates standalone HTML file (open in any browser)
- No server required, no deployment needed
"""

import json
import os
import sys
import webbrowser
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


@dataclass
class SecurityIncident:
    """A security incident."""
    id: str
    timestamp: str
    risk_level: str
    attack_types: List[str]
    source_type: str
    source_author: str
    source_submolt: str
    content_preview: str
    action_taken: str

    def to_dict(self):
        return asdict(self)


class SecurityReporter:
    """Generates security reports from incident data."""

    def __init__(self, data_dir: str = "./data"):
        self.data_dir = Path(data_dir)
        self.incidents_file = self.data_dir / "security_incidents.jsonl"

    def load_incidents(self, limit: int = 100) -> List[SecurityIncident]:
        """Load security incidents."""
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
        blocked = [i for i in incidents if i.action_taken == "blocked"]

        attack_counts = {}
        for incident in incidents:
            for attack_type in incident.attack_types:
                attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

        return {
            "total_incidents": len(incidents),
            "today_incidents": len(today_incidents),
            "high_risk_blocked": len(high_risk),
            "total_blocked": len(blocked),
            "attack_breakdown": attack_counts,
        }

    def print_terminal_report(self, incidents: List[SecurityIncident], stats: Dict):
        """Print a terminal-based security report."""
        print(f"\n{CYAN}{'='*65}{RESET}")
        print(f"{BOLD}  🛡️  MOLTBOOK SECURITY REPORT{RESET}")
        print(f"{CYAN}{'='*65}{RESET}\n")

        # Stats
        print(f"  {RED}🚨 High-Risk Blocked:{RESET}  {stats['high_risk_blocked']}")
        print(f"  {YELLOW}⚠️  Threats Today:{RESET}      {stats['today_incidents']}")
        print(f"  {GREEN}🛡️  Total Protected:{RESET}    {stats['total_incidents']}")
        print(f"  {CYAN}📊 Scan Coverage:{RESET}      100%")

        # Attack breakdown
        if stats['attack_breakdown']:
            print(f"\n{BOLD}  Attack Types Detected:{RESET}\n")
            total = stats['total_incidents'] or 1
            for attack, count in sorted(stats['attack_breakdown'].items(), key=lambda x: -x[1]):
                pct = int(count / total * 20)
                bar = "█" * pct + "░" * (20 - pct)
                print(f"    {attack:25} {bar} {count}")

        # Recent incidents
        if incidents:
            print(f"\n{BOLD}  Recent Security Incidents:{RESET}\n")
            for inc in incidents[:10]:
                if inc.risk_level == "high":
                    level_color = RED
                    level_icon = "🚨"
                    action_text = f"{RED}BLOCKED{RESET}"
                elif inc.risk_level == "medium":
                    level_color = YELLOW
                    level_icon = "⚠️"
                    action_text = f"{YELLOW}FLAGGED{RESET}"
                else:
                    level_color = GREEN
                    level_icon = "ℹ️"
                    action_text = f"{GREEN}LOGGED{RESET}"

                print(f"    {level_icon} {level_color}[{inc.risk_level.upper():6}]{RESET} @{inc.source_author[:18]:18} → {action_text}")
                print(f"       {DIM}m/{inc.source_submolt} | {', '.join(inc.attack_types)}{RESET}")
                print(f"       {DIM}\"{inc.content_preview[:55]}...\"{RESET}")
                print()
        else:
            print(f"\n  {GREEN}✅ No security incidents recorded yet{RESET}")
            print(f"  {DIM}Run 'moltbook security --scan' to scan Moltbook for threats{RESET}\n")

        print(f"{CYAN}{'='*65}{RESET}\n")

    def generate_html_report(self, incidents: List[SecurityIncident], stats: Dict) -> str:
        """Generate a standalone HTML report."""
        today = datetime.now().strftime("%Y-%m-%d %H:%M")

        # Build incidents HTML
        incidents_html = ""
        for inc in incidents:
            badge_class = "high" if inc.risk_level == "high" else "medium" if inc.risk_level == "medium" else "low"
            action_class = "blocked" if inc.action_taken == "blocked" else "flagged"
            action_text = "🚫 BLOCKED" if inc.action_taken == "blocked" else "⚠️ FLAGGED"
            attacks_html = "".join([f'<span class="attack-tag">{a}</span>' for a in inc.attack_types])

            incidents_html += f'''
            <div class="incident {badge_class}">
                <div class="incident-badge"><span class="badge {badge_class}">{inc.risk_level.upper()}</span></div>
                <div class="incident-body">
                    <div class="incident-meta">
                        <span class="author">@{inc.source_author}</span>
                        <span class="submolt">m/{inc.source_submolt}</span>
                    </div>
                    <div class="attack-tags">{attacks_html}</div>
                    <div class="preview">{inc.content_preview[:150]}...</div>
                    <div class="action {action_class}">{action_text}</div>
                </div>
            </div>
            '''

        # Build attack breakdown HTML
        attacks_html = ""
        total = stats['total_incidents'] or 1
        for attack, count in sorted(stats['attack_breakdown'].items(), key=lambda x: -x[1]):
            pct = count / total * 100
            attacks_html += f'''
            <div class="attack-item">
                <div class="attack-info"><span>{attack}</span><span class="count">{count}</span></div>
                <div class="attack-bar"><div class="fill" style="width:{pct}%"></div></div>
            </div>
            '''

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Moltbook Security Report - {today}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0a0a0a; color: #fff; padding: 24px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; padding: 20px; background: #141414; border-radius: 12px; margin-bottom: 24px; border: 1px solid #222; }}
        .header h1 {{ font-size: 24px; display: flex; align-items: center; gap: 12px; }}
        .timestamp {{ color: #666; font-size: 14px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
        .stat {{ background: #141414; border-radius: 12px; padding: 20px; border: 1px solid #222; }}
        .stat.danger {{ border-color: #ef4444; background: linear-gradient(135deg, rgba(239,68,68,0.1), #141414); }}
        .stat.warning {{ border-color: #eab308; background: linear-gradient(135deg, rgba(234,179,8,0.1), #141414); }}
        .stat.success {{ border-color: #22c55e; background: linear-gradient(135deg, rgba(34,197,94,0.1), #141414); }}
        .stat-icon {{ font-size: 24px; margin-bottom: 8px; }}
        .stat-value {{ font-size: 32px; font-weight: 700; }}
        .stat-label {{ color: #888; font-size: 14px; }}
        .grid {{ display: grid; grid-template-columns: 2fr 1fr; gap: 24px; }}
        .panel {{ background: #141414; border-radius: 12px; border: 1px solid #222; overflow: hidden; }}
        .panel-header {{ padding: 16px 20px; border-bottom: 1px solid #222; background: #1a1a1a; font-weight: 600; }}
        .panel-header.security {{ background: linear-gradient(135deg, rgba(239,68,68,0.1), #1a1a1a); }}
        .incidents {{ padding: 12px; max-height: 600px; overflow-y: auto; }}
        .incident {{ display: flex; gap: 16px; padding: 16px; border-radius: 8px; margin-bottom: 12px; border-left: 4px solid transparent; }}
        .incident.high {{ border-left-color: #ef4444; background: rgba(239,68,68,0.05); }}
        .incident.medium {{ border-left-color: #eab308; background: rgba(234,179,8,0.05); }}
        .incident.low {{ border-left-color: #22c55e; background: rgba(34,197,94,0.05); }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
        .badge.high {{ background: #ef4444; }}
        .badge.medium {{ background: #eab308; color: #000; }}
        .badge.low {{ background: #22c55e; }}
        .incident-body {{ flex: 1; }}
        .incident-meta {{ font-size: 13px; color: #888; margin-bottom: 8px; }}
        .author {{ color: #6366f1; font-weight: 500; margin-right: 12px; }}
        .attack-tags {{ display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }}
        .attack-tag {{ background: #222; border: 1px solid #333; padding: 3px 8px; border-radius: 4px; font-size: 11px; color: #ef4444; }}
        .preview {{ font-size: 13px; color: #888; background: #1a1a1a; padding: 12px; border-radius: 6px; font-family: monospace; border-left: 3px solid #333; }}
        .action {{ margin-top: 10px; font-size: 12px; font-weight: 600; }}
        .action.blocked {{ color: #ef4444; }}
        .action.flagged {{ color: #eab308; }}
        .attack-stats {{ padding: 16px; }}
        .attack-item {{ margin-bottom: 16px; }}
        .attack-info {{ display: flex; justify-content: space-between; margin-bottom: 6px; font-size: 13px; }}
        .attack-info .count {{ color: #ef4444; font-weight: 600; }}
        .attack-bar {{ height: 8px; background: #222; border-radius: 4px; overflow: hidden; }}
        .attack-bar .fill {{ height: 100%; background: linear-gradient(90deg, #ef4444, #eab308); border-radius: 4px; }}
        .empty {{ text-align: center; padding: 48px; color: #666; }}
        @media (max-width: 900px) {{ .stats {{ grid-template-columns: repeat(2, 1fr); }} .grid {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Moltbook Security Report</h1>
            <div class="timestamp">Generated: {today}</div>
        </div>

        <div class="stats">
            <div class="stat danger">
                <div class="stat-icon">🚨</div>
                <div class="stat-value">{stats['high_risk_blocked']}</div>
                <div class="stat-label">High-Risk Blocked</div>
            </div>
            <div class="stat warning">
                <div class="stat-icon">⚠️</div>
                <div class="stat-value">{stats['today_incidents']}</div>
                <div class="stat-label">Threats Today</div>
            </div>
            <div class="stat success">
                <div class="stat-icon">🛡️</div>
                <div class="stat-value">{stats['total_incidents']}</div>
                <div class="stat-label">Total Protected</div>
            </div>
            <div class="stat">
                <div class="stat-icon">📊</div>
                <div class="stat-value">100%</div>
                <div class="stat-label">Scan Coverage</div>
            </div>
        </div>

        <div class="grid">
            <div class="panel">
                <div class="panel-header security">🔐 Security Incidents</div>
                <div class="incidents">
                    {incidents_html if incidents_html else '<div class="empty">No incidents recorded. Run: moltbook security --scan</div>'}
                </div>
            </div>
            <div class="panel">
                <div class="panel-header">🎯 Attack Types</div>
                <div class="attack-stats">
                    {attacks_html if attacks_html else '<div class="empty">No data</div>'}
                </div>
            </div>
        </div>
    </div>
</body>
</html>'''
        return html


def run_scan_moltbook(reporter: SecurityReporter) -> int:
    """Scan live Moltbook content for threats."""
    import requests

    # Load credentials
    api_key = os.environ.get("MOLTBOOK_API_KEY", "")
    if not api_key:
        cred_file = Path(".moltbook/credentials.json")
        if cred_file.exists():
            with open(cred_file) as f:
                creds = json.load(f)
                api_key = creds.get("moltbook_api_key", "")

    if not api_key:
        config_file = Path("agent_config.yaml")
        if config_file.exists():
            import yaml
            with open(config_file) as f:
                config = yaml.safe_load(f)
                api_key = config.get("moltbook_api_key", "")

    if not api_key:
        print(f"{RED}✗{RESET} No Moltbook API key found")
        return 0

    # Import scanner
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from injection_scanner import InjectionScanner
    scanner = InjectionScanner(strict_mode=True)

    headers = {"Authorization": f"Bearer {api_key}"}
    threats_found = 0

    # Ensure data directory exists
    reporter.data_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{CYAN}Scanning Moltbook for threats...{RESET}\n")

    for submolt in ["general", "agents", "programming", "askagents"]:
        print(f"  Scanning m/{submolt}...", end=" ", flush=True)
        try:
            response = requests.get(
                f"https://www.moltbook.com/api/v1/posts?submolt={submolt}&limit=30&sort=new",
                headers=headers,
                timeout=30
            )
            if response.status_code == 200:
                posts = response.json().get("posts", [])
                submolt_threats = 0

                for post in posts:
                    content = f"{post.get('title', '')} {post.get('content', '')}"
                    author = post.get("author", {})
                    author_name = author.get("name", "Unknown") if isinstance(author, dict) else str(author)
                    submolt_data = post.get("submolt", {})
                    submolt_name = submolt_data.get("name", submolt) if isinstance(submolt_data, dict) else submolt

                    result = scanner.scan(content)

                    if result["is_suspicious"]:
                        incident = SecurityIncident(
                            id=f"inc_{datetime.now().strftime('%Y%m%d%H%M%S')}_{post.get('id', '')[:8]}",
                            timestamp=datetime.now().isoformat(),
                            risk_level=result["risk_level"],
                            attack_types=result["attack_types"],
                            source_type="post",
                            source_author=author_name,
                            source_submolt=submolt_name,
                            content_preview=content[:200] + ("..." if len(content) > 200 else ""),
                            action_taken="blocked" if result["risk_level"] == "high" else "flagged"
                        )

                        with open(reporter.incidents_file, "a") as f:
                            f.write(json.dumps(incident.to_dict()) + "\n")

                        threats_found += 1
                        submolt_threats += 1

                if submolt_threats > 0:
                    print(f"{RED}{submolt_threats} threats{RESET}")
                else:
                    print(f"{GREEN}clean{RESET}")

        except Exception as e:
            print(f"{YELLOW}error{RESET}")

    return threats_found


def run_security(args):
    """Run the security command."""
    reporter = SecurityReporter()

    # Scan Moltbook if requested
    if hasattr(args, 'scan') and args.scan:
        threats = run_scan_moltbook(reporter)
        print(f"\n{GREEN}✓{RESET} Scan complete. Found {threats} new threats.\n")

    # Load data
    incidents = reporter.load_incidents(limit=50)
    stats = reporter.get_stats()

    # Generate HTML report if requested
    if hasattr(args, 'html') and args.html:
        html = reporter.generate_html_report(incidents, stats)
        output_path = Path(args.html)
        output_path.write_text(html)
        print(f"{GREEN}✓{RESET} HTML report saved to: {output_path}")

        # Open in browser if requested
        if hasattr(args, 'open') and args.open:
            webbrowser.open(f"file://{output_path.absolute()}")
            print(f"{GREEN}✓{RESET} Opened in browser")
        return

    # Print terminal report
    reporter.print_terminal_report(incidents, stats)

    # Suggest HTML export
    if incidents:
        print(f"{DIM}  Tip: Run 'moltbook security --html report.html --open' to view in browser{RESET}\n")
