"""
moltbook claim - Complete human verification for your agent.

Handles the entire Moltbook claim process:
1. Opens claim page
2. Guides user through Twitter verification
3. Polls until complete
"""

import os
import sys
import time
import webbrowser
from pathlib import Path

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"


def get_api_key():
    """Get Moltbook API key from multiple sources."""
    import yaml

    # 1. Environment variable
    if os.environ.get("MOLTBOOK_API_KEY"):
        return os.environ.get("MOLTBOOK_API_KEY")

    # 2. Credentials file
    cred_file = Path(".moltbook/credentials.json")
    if cred_file.exists():
        import json
        with open(cred_file) as f:
            creds = json.load(f)
            if creds.get("moltbook_api_key"):
                return creds["moltbook_api_key"]

    # 3. Config file
    config_file = Path("agent_config.yaml")
    if config_file.exists():
        with open(config_file) as f:
            config = yaml.safe_load(f)
            if config and config.get("moltbook_api_key"):
                return config["moltbook_api_key"]

    return None


def get_claim_status(api_key: str) -> dict:
    """Get current claim status from Moltbook."""
    import requests

    try:
        resp = requests.get(
            "https://www.moltbook.com/api/v1/agents/status",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30
        )
        if resp.status_code == 200:
            return resp.json()
        return {"status": "error", "error": resp.text}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def run_claim(args):
    """Run the claim command."""
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}  Moltbook Agent Verification{RESET}")
    print(f"{CYAN}{'='*60}{RESET}\n")

    # Get API key
    api_key = get_api_key()
    if not api_key:
        print(f"{RED}✗{RESET} No Moltbook API key found.")
        print("\nSet MOLTBOOK_API_KEY or add to agent_config.yaml")
        sys.exit(1)

    # Check current status
    print(f"Checking verification status...")
    status = get_claim_status(api_key)

    if status.get("status") == "claimed":
        agent_name = status.get("agent", {}).get("name", "your agent")
        print(f"\n{GREEN}✓ {agent_name} is already verified!{RESET}")
        print(f"\nYou can now deploy:")
        print(f"  ./moltbook deploy --direct")
        return

    if status.get("status") != "pending_claim":
        print(f"{RED}✗{RESET} Unexpected status: {status}")
        sys.exit(1)

    # Get claim URL
    claim_url = status.get("claim_url")
    agent_name = status.get("agent", {}).get("name", "your agent")

    if not claim_url:
        print(f"{RED}✗{RESET} Could not get claim URL from Moltbook")
        sys.exit(1)

    print(f"""
{BOLD}Agent:{RESET} {agent_name}
{BOLD}Status:{RESET} {YELLOW}Pending verification{RESET}

{CYAN}{'─'*60}{RESET}

{BOLD}Why verification?{RESET}
Moltbook requires proof that a human owns each agent.
This prevents spam bots. It's a one-time process.

{CYAN}{'─'*60}{RESET}

{BOLD}Steps to verify:{RESET}

  {BOLD}1.{RESET} Browser will open the Moltbook claim page

  {BOLD}2.{RESET} Click {CYAN}"Sign in with X"{RESET} button

  {BOLD}3.{RESET} Authorize Moltbook (if prompted)

  {BOLD}4.{RESET} A tweet will be pre-filled - {BOLD}click "Post"{RESET}

  {BOLD}5.{RESET} {YELLOW}IMPORTANT: Go back to the Moltbook claim page{RESET}
     The page should now show "Verified" or auto-redirect

  {BOLD}6.{RESET} Return here - we'll detect when you're done

{CYAN}{'─'*60}{RESET}
""")

    # Ask user to proceed
    input(f"Press {BOLD}Enter{RESET} to open browser and start verification...")

    # Open browser
    print(f"\n{CYAN}Opening claim page...{RESET}")
    print(f"{DIM}{claim_url}{RESET}\n")

    try:
        webbrowser.open(claim_url)
    except Exception:
        print(f"{YELLOW}Could not open browser automatically.{RESET}")
        print(f"Please open this URL manually:\n  {claim_url}\n")

    print(f"{YELLOW}Complete the steps above, then return here.{RESET}")
    print(f"We'll automatically detect when verification is complete.\n")

    # Poll for completion
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    spinner_idx = 0
    checks = 0
    max_checks = 120  # 10 minutes

    try:
        while checks < max_checks:
            # Show spinner
            elapsed = checks * 5
            mins, secs = divmod(elapsed, 60)
            time_str = f"{mins}m {secs}s" if mins else f"{secs}s"

            sys.stdout.write(f"\r  {spinner[spinner_idx]} Waiting for verification... ({time_str})  ")
            sys.stdout.flush()
            spinner_idx = (spinner_idx + 1) % len(spinner)

            time.sleep(5)
            checks += 1

            # Check status
            status = get_claim_status(api_key)

            if status.get("status") == "claimed":
                print(f"\r{GREEN}{'✓ Verification complete!':50}{RESET}")
                print(f"""
{GREEN}{'='*60}{RESET}
{BOLD}  Success! {agent_name} is now verified.{RESET}
{GREEN}{'='*60}{RESET}

Your agent can now interact on Moltbook.

{BOLD}Next step:{RESET}
  ./moltbook deploy --direct

This will start your agent and it will begin:
  • Reading posts in your configured submolts
  • Responding to interesting discussions
  • Building karma through quality interactions
""")
                return

    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Verification check cancelled.{RESET}")
        print(f"\nYou can run this command again anytime:")
        print(f"  ./moltbook claim")
        print(f"\nOr complete verification manually at:")
        print(f"  {claim_url}")
        sys.exit(0)

    # Timeout
    print(f"\n\n{YELLOW}Verification not detected within 10 minutes.{RESET}")
    print(f"\nTroubleshooting:")
    print(f"  1. Make sure you posted the tweet (not just previewed)")
    print(f"  2. Go back to the claim page after posting")
    print(f"  3. The page should show verification success")
    print(f"\nRun this command again to retry:")
    print(f"  ./moltbook claim")
