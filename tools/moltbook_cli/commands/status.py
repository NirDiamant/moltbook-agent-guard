"""
moltbook status - Check agent status.
"""

import json
import subprocess
import sys
from pathlib import Path
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


def get_container_status(agent_name):
    """Get Docker container status."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name=moltbook-{agent_name.lower()}",
             "--format", "{{.Status}}|{{.State}}|{{.CreatedAt}}"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split("|")
            return {
                "status": parts[0] if len(parts) > 0 else "Unknown",
                "state": parts[1] if len(parts) > 1 else "unknown",
                "created": parts[2] if len(parts) > 2 else "Unknown",
            }
    except Exception:
        pass
    return None


def get_moltbook_stats(api_key, agent_name):
    """Get stats from Moltbook API."""
    try:
        import requests
        response = requests.get(
            "https://www.moltbook.com/api/v1/agents/me",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=10
        )
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None


def run_status(args):
    """Run the status command."""
    config = load_config()
    credentials = load_credentials()

    if not config:
        print(f"{RED}✗{RESET} No configuration found. Run 'moltbook init' first.")
        sys.exit(1)

    agent_name = config.get("agent", {}).get("name", "Unknown")
    archetype = config.get("agent", {}).get("archetype", "custom")

    # Build status object
    status = {
        "agent": {
            "name": agent_name,
            "archetype": archetype,
        },
        "container": None,
        "moltbook": None,
        "security": config.get("security", {}),
    }

    # Get container status
    container = get_container_status(agent_name)
    status["container"] = container

    # Get Moltbook stats
    if credentials and credentials.get("moltbook_api_key"):
        moltbook = get_moltbook_stats(credentials["moltbook_api_key"], agent_name)
        status["moltbook"] = moltbook

    # Output
    if args.json:
        print(json.dumps(status, indent=2, default=str))
        return

    # Pretty print
    print(f"\n{CYAN}{'='*50}{RESET}")
    print(f"{BOLD}  Moltbook Agent Status{RESET}")
    print(f"{CYAN}{'='*50}{RESET}\n")

    # Agent info
    print(f"{BOLD}Agent{RESET}")
    print(f"  Name:      {agent_name}")
    print(f"  Archetype: {archetype}")
    print(f"  Profile:   https://moltbook.com/agent/{agent_name}")

    # Container status
    print(f"\n{BOLD}Container{RESET}")
    if container:
        state = container.get("state", "unknown")
        if state == "running":
            print(f"  Status: {GREEN}● Running{RESET}")
        elif state == "exited":
            print(f"  Status: {RED}● Stopped{RESET}")
        else:
            print(f"  Status: {YELLOW}● {state.title()}{RESET}")
        print(f"  Details: {container.get('status', 'Unknown')}")
        print(f"  Created: {container.get('created', 'Unknown')}")
    else:
        print(f"  Status: {YELLOW}● Not deployed{RESET}")
        print(f"  Run 'moltbook deploy' to start")

    # Moltbook stats
    print(f"\n{BOLD}Moltbook{RESET}")
    if status["moltbook"]:
        mb = status["moltbook"]
        print(f"  Karma:     {mb.get('karma', 0)}")
        print(f"  Posts:     {mb.get('post_count', 0)}")
        print(f"  Comments:  {mb.get('comment_count', 0)}")
        print(f"  Following: {mb.get('following_count', 0)}")
        print(f"  Followers: {mb.get('follower_count', 0)}")
    elif credentials and credentials.get("moltbook_api_key"):
        print(f"  {YELLOW}Could not fetch stats{RESET}")
    else:
        print(f"  {YELLOW}Not registered{RESET}")
        print(f"  Run 'moltbook init' to register")

    # Security
    print(f"\n{BOLD}Security{RESET}")
    security = status.get("security", {})
    scanner = security.get("injection_scanner", False)
    budget = security.get("budget_enabled", False)
    monthly = security.get("monthly_budget", 0)

    if scanner:
        print(f"  Injection Scanner: {GREEN}● Enabled{RESET}")
    else:
        print(f"  Injection Scanner: {RED}● Disabled{RESET}")

    if budget:
        print(f"  Budget Control:    {GREEN}● Enabled{RESET} (${monthly:.2f}/month)")
    else:
        print(f"  Budget Control:    {YELLOW}● Disabled{RESET}")

    # Verbose mode
    if args.verbose:
        print(f"\n{BOLD}Configuration{RESET}")
        print(f"  Config:      .moltbook/config.json")
        print(f"  Credentials: .moltbook/credentials.json")
        print(f"  SOUL:        .moltbook/SOUL.md")
        print(f"  Guidelines:  .moltbook/AGENTS.md")

        print(f"\n{BOLD}Quick Commands{RESET}")
        print(f"  moltbook deploy      - Start/restart agent")
        print(f"  moltbook scan        - Scan for threats")
        print(f"  moltbook observatory - Open dashboard")
        print(f"  docker compose logs  - View logs")

    print()
