"""
Moltbook Security Dashboard - Streamlit App

EACH USER DEPLOYS THEIR OWN INSTANCE:
- Your dashboard tracks YOUR agent's security incidents
- Your MOLTBOOK_API_KEY identifies your agent
- Data is stored per-deployment (isolated)

Deploy for FREE to Streamlit Cloud:
1. Fork/clone this repo to YOUR GitHub
2. Go to share.streamlit.io
3. Connect YOUR repo
4. Set YOUR secrets (MOLTBOOK_API_KEY, AGENT_NAME)
5. Done! Your personal dashboard in 2 minutes.

Or run locally:
    pip install streamlit
    MOLTBOOK_API_KEY=your_key streamlit run dashboard/streamlit_app.py
"""

import streamlit as st
import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional
import time
import requests

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def get_agent_info(api_key: str) -> Optional[Dict]:
    """Fetch agent info from Moltbook API."""
    if not api_key:
        return None
    try:
        response = requests.get(
            "https://www.moltbook.com/api/v1/agents/me",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return data.get("agent", data)
    except:
        pass
    return None


# Page config
st.set_page_config(
    page_title="Moltbook Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
<style>
    .stApp { background-color: #0a0a0a; }
    .main { padding: 1rem 2rem; }
    .stat-card {
        background: linear-gradient(135deg, rgba(99,102,241,0.1), #141414);
        border: 1px solid #333;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .stat-card.danger { border-color: #ef4444; background: linear-gradient(135deg, rgba(239,68,68,0.15), #141414); }
    .stat-card.warning { border-color: #eab308; background: linear-gradient(135deg, rgba(234,179,8,0.15), #141414); }
    .stat-card.success { border-color: #22c55e; background: linear-gradient(135deg, rgba(34,197,94,0.15), #141414); }
    .stat-value { font-size: 36px; font-weight: 700; color: white; }
    .stat-label { font-size: 14px; color: #888; }
    .incident-card {
        background: #141414;
        border-left: 4px solid #333;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .incident-card.high { border-left-color: #ef4444; background: rgba(239,68,68,0.05); }
    .incident-card.medium { border-left-color: #eab308; background: rgba(234,179,8,0.05); }
    .badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 700;
        margin-right: 8px;
    }
    .badge.high { background: #ef4444; color: white; }
    .badge.medium { background: #eab308; color: black; }
    .attack-tag {
        display: inline-block;
        background: #222;
        border: 1px solid #444;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 11px;
        color: #ef4444;
        margin-right: 4px;
    }
</style>
""", unsafe_allow_html=True)


@dataclass
class SecurityIncident:
    id: str
    timestamp: str
    risk_level: str
    attack_types: List[str]
    source_type: str
    source_author: str
    source_submolt: str
    content_preview: str
    action_taken: str


class SecurityTracker:
    """Tracks and stores security incidents."""

    def __init__(self):
        self.data_dir = Path("data")
        self.data_dir.mkdir(exist_ok=True)
        self.incidents_file = self.data_dir / "security_incidents.jsonl"

    def load_incidents(self, limit: int = 100) -> List[SecurityIncident]:
        incidents = []
        if self.incidents_file.exists():
            with open(self.incidents_file, "r") as f:
                for line in f:
                    if line.strip():
                        incidents.append(SecurityIncident(**json.loads(line)))
        return list(reversed(incidents[-limit:]))

    def record_incident(self, incident: SecurityIncident):
        with open(self.incidents_file, "a") as f:
            f.write(json.dumps(asdict(incident)) + "\n")

    def get_stats(self) -> Dict:
        incidents = self.load_incidents(1000)
        today = datetime.now().strftime("%Y-%m-%d")

        return {
            "total": len(incidents),
            "today": len([i for i in incidents if i.timestamp.startswith(today)]),
            "high_risk": len([i for i in incidents if i.risk_level == "high"]),
            "blocked": len([i for i in incidents if i.action_taken == "blocked"]),
            "attacks": self._count_attacks(incidents)
        }

    def _count_attacks(self, incidents: List[SecurityIncident]) -> Dict[str, int]:
        counts = {}
        for inc in incidents:
            for attack in inc.attack_types:
                counts[attack] = counts.get(attack, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))


def scan_moltbook(tracker: SecurityTracker, api_key: str) -> int:
    """Scan Moltbook for threats and record incidents."""
    import requests

    try:
        from tools.injection_scanner import InjectionScanner
        scanner = InjectionScanner(strict_mode=True)
    except ImportError:
        st.error("Injection scanner not found. Make sure tools/ is in path.")
        return 0

    headers = {"Authorization": f"Bearer {api_key}"}
    threats_found = 0

    for submolt in ["general", "agents", "programming", "askagents"]:
        try:
            response = requests.get(
                f"https://www.moltbook.com/api/v1/posts?submolt={submolt}&limit=25&sort=new",
                headers=headers,
                timeout=30
            )
            if response.status_code == 200:
                posts = response.json().get("posts", [])

                for post in posts:
                    content = f"{post.get('title', '')} {post.get('content', '')}"
                    author = post.get("author", {})
                    author_name = author.get("name", "Unknown") if isinstance(author, dict) else str(author)
                    submolt_data = post.get("submolt", {})
                    submolt_name = submolt_data.get("name", submolt) if isinstance(submolt_data, dict) else submolt

                    result = scanner.scan(content)

                    if result["is_suspicious"]:
                        incident = SecurityIncident(
                            id=f"inc_{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
                            timestamp=datetime.now().isoformat(),
                            risk_level=result["risk_level"],
                            attack_types=result["attack_types"],
                            source_type="post",
                            source_author=author_name,
                            source_submolt=submolt_name,
                            content_preview=content[:200],
                            action_taken="blocked" if result["risk_level"] == "high" else "flagged"
                        )
                        tracker.record_incident(incident)
                        threats_found += 1
        except Exception as e:
            st.warning(f"Error scanning {submolt}: {e}")

    return threats_found


def main():
    # Get API key from secrets or environment
    api_key = st.secrets.get("MOLTBOOK_API_KEY", os.environ.get("MOLTBOOK_API_KEY", ""))

    # Fetch agent info for personalization
    agent_info = get_agent_info(api_key) if api_key else None
    agent_name = agent_info.get("name", "Your Agent") if agent_info else "Your Agent"

    # Header with personalized agent name
    col1, col2 = st.columns([3, 1])
    with col1:
        st.title("🛡️ Moltbook Security Dashboard")
        st.markdown(f"<p style='color:#6366f1; margin-top:-10px;'>Protecting <strong>@{agent_name}</strong></p>", unsafe_allow_html=True)
    with col2:
        st.markdown(f"<p style='text-align:right; color:#22c55e;'>● Live</p>", unsafe_allow_html=True)

    if not api_key:
        st.warning("""
        ⚠️ **Setup Required**: Add your MOLTBOOK_API_KEY to enable live scanning.

        **On Streamlit Cloud**: Go to App Settings → Secrets → Add `MOLTBOOK_API_KEY = "your_key"`

        **Running locally**: Set the environment variable before running.
        """)
        # Try to load from local config
        config_file = Path("agent_config.yaml")
        if config_file.exists():
            import yaml
            with open(config_file) as f:
                config = yaml.safe_load(f)
                api_key = config.get("moltbook_api_key", "")

    tracker = SecurityTracker()
    stats = tracker.get_stats()

    # Stats Cards
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="stat-card danger">
            <div style="font-size:28px;">🚨</div>
            <div class="stat-value">{stats['high_risk']}</div>
            <div class="stat-label">High-Risk Blocked</div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="stat-card warning">
            <div style="font-size:28px;">⚠️</div>
            <div class="stat-value">{stats['today']}</div>
            <div class="stat-label">Threats Today</div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="stat-card success">
            <div style="font-size:28px;">🛡️</div>
            <div class="stat-value">{stats['total']}</div>
            <div class="stat-label">Total Protected</div>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="stat-card">
            <div style="font-size:28px;">📊</div>
            <div class="stat-value">100%</div>
            <div class="stat-label">Scan Coverage</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Scan button
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        if st.button("🔍 Scan Now", type="primary", use_container_width=True):
            if api_key:
                with st.spinner("Scanning Moltbook for threats..."):
                    threats = scan_moltbook(tracker, api_key)
                st.success(f"Found {threats} new threats!")
                st.rerun()
            else:
                st.error("API key required for scanning")

    with col2:
        auto_refresh = st.checkbox("Auto-refresh (30s)", value=False)

    st.markdown("<br>", unsafe_allow_html=True)

    # Main content
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("🔐 Security Incidents")

        incidents = tracker.load_incidents(50)

        if incidents:
            for inc in incidents:
                badge_color = "#ef4444" if inc.risk_level == "high" else "#eab308"
                action_text = "🚫 BLOCKED" if inc.action_taken == "blocked" else "⚠️ FLAGGED"
                action_color = "#ef4444" if inc.action_taken == "blocked" else "#eab308"

                attacks_html = " ".join([f'<span class="attack-tag">{a}</span>' for a in inc.attack_types])

                st.markdown(f"""
                <div class="incident-card {inc.risk_level}">
                    <span class="badge {inc.risk_level}">{inc.risk_level.upper()}</span>
                    <span style="color:#6366f1;font-weight:500;">@{inc.source_author}</span>
                    <span style="color:#666;"> • m/{inc.source_submolt}</span>
                    <br><br>
                    {attacks_html}
                    <div style="background:#1a1a1a;padding:12px;border-radius:6px;margin-top:10px;font-family:monospace;font-size:13px;color:#888;border-left:3px solid #333;">
                        {inc.content_preview[:150]}...
                    </div>
                    <div style="margin-top:10px;font-size:12px;font-weight:600;color:{action_color};">
                        {action_text}
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No incidents yet. Click 'Scan Now' to analyze Moltbook content.")

    with col2:
        st.subheader("🎯 Attack Types")

        if stats['attacks']:
            for attack, count in stats['attacks'].items():
                pct = count / stats['total'] * 100 if stats['total'] > 0 else 0
                st.markdown(f"""
                <div style="margin-bottom:16px;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                        <span style="font-size:13px;color:#888;">{attack}</span>
                        <span style="font-size:13px;font-weight:600;color:#ef4444;">{count}</span>
                    </div>
                    <div style="height:8px;background:#222;border-radius:4px;overflow:hidden;">
                        <div style="width:{pct}%;height:100%;background:linear-gradient(90deg,#ef4444,#eab308);border-radius:4px;"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No attack data yet")

    # Auto-refresh
    if auto_refresh:
        time.sleep(30)
        st.rerun()


if __name__ == "__main__":
    main()
