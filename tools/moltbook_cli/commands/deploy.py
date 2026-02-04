"""
moltbook deploy - Deploy your agent to Moltbook.

Supports two deployment modes:
1. Direct: Run the agent in the current process (--direct)
2. Docker: Run in a Docker container (default)

Handles the full lifecycle:
- Agent registration (if needed)
- Human claim verification (opens browser, waits for completion)
- Deployment
"""

import json
import os
import subprocess
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


def load_config():
    """Load project configuration."""
    config_file = Path(".moltbook/config.json")
    if not config_file.exists():
        return None
    with open(config_file) as f:
        return json.load(f)


def get_api_key(config_path: str = None):
    """Get Moltbook API key from multiple sources."""
    import yaml

    # 1. Environment variable
    if os.environ.get("MOLTBOOK_API_KEY"):
        return os.environ.get("MOLTBOOK_API_KEY")

    # 2. Credentials file
    cred_file = Path(".moltbook/credentials.json")
    if cred_file.exists():
        with open(cred_file) as f:
            creds = json.load(f)
            if creds.get("moltbook_api_key"):
                return creds["moltbook_api_key"]

    # 3. Custom config file (if specified)
    if config_path:
        config_file = Path(config_path)
        if config_file.exists():
            with open(config_file) as f:
                config = yaml.safe_load(f)
                if config and config.get("moltbook_api_key"):
                    return config["moltbook_api_key"]

    # 4. Default config file
    config_file = Path("agent_config.yaml")
    if config_file.exists():
        with open(config_file) as f:
            config = yaml.safe_load(f)
            if config and config.get("moltbook_api_key"):
                return config["moltbook_api_key"]

    return None


def register_agent(name: str, description: str) -> dict:
    """Register a new agent on Moltbook."""
    import requests

    print(f"\n{CYAN}Registering agent '{name}' on Moltbook...{RESET}")

    try:
        response = requests.post(
            "https://www.moltbook.com/api/v1/agents/register",
            json={"name": name, "description": description},
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            print(f"{GREEN}✓{RESET} Agent registered successfully!")
            return data
        elif response.status_code == 409:
            print(f"{YELLOW}⚠{RESET} Agent name already taken.")
            return {"error": "name_taken"}
        else:
            data = response.json()
            print(f"{RED}✗{RESET} Registration failed: {data.get('error', response.status_code)}")
            return {"error": data.get("error", str(response.status_code))}
    except Exception as e:
        print(f"{RED}✗{RESET} Registration error: {e}")
        return {"error": str(e)}


def check_claim_status(api_key: str) -> dict:
    """Check if agent is claimed."""
    import requests

    try:
        response = requests.get(
            "https://www.moltbook.com/api/v1/agents/status",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=30
        )

        if response.status_code == 200:
            return response.json()
        else:
            return {"status": "error", "error": response.text}
    except Exception as e:
        return {"status": "error", "error": str(e)}


def wait_for_claim(api_key: str, claim_url: str) -> bool:
    """
    Open browser to claim URL and wait for human verification.

    Returns True if claimed, False if user cancels.
    """
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}  Human Verification Required{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    print(f"""
Moltbook requires human verification to prevent spam bots.
This is a one-time process.

{BOLD}Steps:{RESET}
  1. Browser will open the claim page
  2. Click the Twitter/X verification button
  3. Post the verification tweet
  4. Return here - we'll detect when you're verified

{DIM}Claim URL: {claim_url}{RESET}
""")

    # Open browser
    print(f"{CYAN}Opening browser...{RESET}")
    try:
        webbrowser.open(claim_url)
    except Exception as e:
        print(f"{YELLOW}⚠{RESET} Could not open browser automatically.")
        print(f"Please open this URL manually:\n  {claim_url}")

    print(f"\n{YELLOW}Waiting for verification...{RESET} (Press Ctrl+C to cancel)\n")

    # Poll for claim status
    spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
    spinner_idx = 0
    check_count = 0

    try:
        while True:
            # Show spinner
            sys.stdout.write(f"\r  {spinner[spinner_idx]} Checking status...")
            sys.stdout.flush()
            spinner_idx = (spinner_idx + 1) % len(spinner)

            # Check every 5 seconds
            time.sleep(5)
            check_count += 1

            status = check_claim_status(api_key)

            if status.get("status") == "claimed":
                sys.stdout.write(f"\r{GREEN}✓ Verification complete!{RESET}           \n")
                return True
            elif status.get("status") == "error":
                # Might be temporary, keep trying
                if check_count > 60:  # Give up after 5 minutes
                    print(f"\n{RED}✗{RESET} Verification timed out.")
                    return False

            # Show progress every minute
            if check_count % 12 == 0:
                mins = check_count // 12
                sys.stdout.write(f"\r  {spinner[spinner_idx]} Still waiting... ({mins}m elapsed)")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print(f"\n\n{YELLOW}Verification cancelled.{RESET}")
        print(f"You can complete verification later at:")
        print(f"  {claim_url}")
        return False


def ensure_agent_claimed(api_key: str, agent_name: str) -> bool:
    """
    Ensure agent is claimed before deployment.

    Handles:
    - Checking current status
    - Guiding user through claim if needed
    - Waiting for claim completion

    Returns True if agent is claimed and ready.
    """
    print(f"\n{CYAN}Checking agent status...{RESET}")

    status = check_claim_status(api_key)

    if status.get("status") == "claimed":
        print(f"{GREEN}✓{RESET} Agent is verified and ready")
        return True

    if status.get("status") == "pending_claim":
        claim_url = status.get("claim_url")
        if not claim_url:
            # Try to construct it from claim token if available
            claim_token = status.get("claim_token")
            if claim_token:
                claim_url = f"https://moltbook.com/claim/{claim_token}"
            else:
                print(f"{RED}✗{RESET} Could not get claim URL. Please contact Moltbook support.")
                return False

        return wait_for_claim(api_key, claim_url)

    if status.get("status") == "error":
        error = status.get("error", "Unknown error")

        # Check if it's a "not found" error - might need to register
        if "not found" in error.lower() or "404" in error:
            print(f"{YELLOW}⚠{RESET} Agent not found on Moltbook.")
            print("The agent may need to be registered first.")
            return False

        # Check for hint about claim URL
        if "claim" in error.lower():
            # Parse claim URL from error message if present
            import re
            url_match = re.search(r'https://moltbook\.com/claim/[^\s\)]+', error)
            if url_match:
                claim_url = url_match.group(0)
                return wait_for_claim(api_key, claim_url)

        print(f"{RED}✗{RESET} Status check failed: {error}")
        return False

    print(f"{YELLOW}⚠{RESET} Unknown status: {status}")
    return False


def load_credentials():
    """Load credentials."""
    cred_file = Path(".moltbook/credentials.json")
    if not cred_file.exists():
        return None
    with open(cred_file) as f:
        return json.load(f)


def load_agent_config(config_path: str = None):
    """Load agent config from specified path or default agent_config.yaml."""
    path = Path(config_path) if config_path else Path("agent_config.yaml")
    if not path.exists():
        return None
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        print(f"{YELLOW}⚠{RESET} PyYAML not installed. Run: pip install pyyaml")
        return None


def run_direct_mode(config, credentials, config_path: str = None):
    """Run the agent directly (not in Docker)."""
    print(f"\n{CYAN}Starting agent in direct mode...{RESET}\n")

    # Determine config file path
    actual_config_path = config_path or "agent_config.yaml"

    # Check for agent config
    agent_config = load_agent_config(config_path)
    if not agent_config:
        if config_path:
            print(f"{RED}✗{RESET} Config file not found: {config_path}")
            sys.exit(1)

        # Try to create from .moltbook config
        template_path = Path(__file__).parent.parent.parent.parent / "agent_config.template.yaml"

        if template_path.exists():
            print(f"{YELLOW}⚠{RESET} No agent_config.yaml found.")
            print(f"Copy the template and fill in your values:")
            print(f"  cp agent_config.template.yaml agent_config.yaml")
            print(f"  # Edit agent_config.yaml with your settings")
            sys.exit(1)
        else:
            print(f"{RED}✗{RESET} No agent configuration found.")
            sys.exit(1)

    # Get API key (check custom config first)
    api_key = get_api_key(config_path)
    if not api_key:
        print(f"{RED}✗{RESET} No Moltbook API key found.")
        print(f"Set MOLTBOOK_API_KEY or add to {actual_config_path}")
        sys.exit(1)

    agent_name = agent_config.get("name", "Unknown")

    # Ensure agent is claimed before deploying
    if not ensure_agent_claimed(api_key, agent_name):
        print(f"\n{RED}✗{RESET} Agent must be claimed before deployment.")
        print("Run this command again after completing verification.")
        sys.exit(1)

    try:
        from tools.agent import MoltbookAgent

        agent = MoltbookAgent.from_config(actual_config_path)

        print(f"\n{GREEN}✓{RESET} Agent initialized: {agent.config.name}")
        print(f"{BOLD}Archetype:{RESET}  {agent.config.archetype}")
        print(f"{BOLD}Submolts:{RESET}   {', '.join(agent.config.submolts)}")
        print(f"{BOLD}LLM:{RESET}        {agent.config.llm_provider}/{agent.config.llm_model}")
        print(f"{BOLD}Budget:{RESET}     ${agent.config.daily_budget}/day, ${agent.config.monthly_budget}/month")
        print()
        print(f"{CYAN}Press Ctrl+C to stop the agent{RESET}\n")

        # Start the agent loop
        agent.run()

    except ImportError as e:
        print(f"{RED}✗{RESET} Missing dependencies: {e}")
        print("Install required packages:")
        print("  pip install anthropic requests pyyaml")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Agent stopped by user{RESET}")
    except Exception as e:
        print(f"{RED}✗{RESET} Agent error: {e}")
        sys.exit(1)


def run_docker_mode(config, credentials, args):
    """Run the agent in Docker."""
    agent_name = config.get("agent", {}).get("name", "Unknown")

    # Check for docker-compose.yml
    if not Path("docker-compose.yml").exists():
        print(f"{RED}✗{RESET} No docker-compose.yml found.")
        print("Run 'moltbook init' to create project structure.")
        sys.exit(1)

    print(f"\n{CYAN}Starting Docker container...{RESET}")

    try:
        # Pull/build image first
        print("Building/pulling OpenClaw image...")
        result = subprocess.run(
            ["docker", "compose", "build"],
            capture_output=True,
            text=True,
            timeout=300
        )

        # Start container
        print("Starting container...")
        result = subprocess.run(
            ["docker", "compose", "up", "-d"],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode == 0:
            print(f"\n{GREEN}✓ Agent deployed successfully!{RESET}")
            print(f"""
{BOLD}Your agent is now running.{RESET}

  Dashboard:    http://127.0.0.1:18789/
  Agent:        {agent_name}
  Container:    moltbook-{agent_name.lower()}

{BOLD}Commands:{RESET}
  moltbook status       - Check agent status
  moltbook observatory  - View monitoring dashboard
  moltbook scan         - Scan for security threats

{BOLD}Logs:{RESET}
  docker compose logs -f
""")
        else:
            print(f"{RED}✗{RESET} Deployment failed:")
            print(result.stderr)
            sys.exit(1)

    except subprocess.TimeoutExpired:
        print(f"{RED}✗{RESET} Deployment timed out")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{RED}✗{RESET} Docker not found. Is Docker installed?")
        print(f"\nTip: Use --direct flag to run without Docker:")
        print(f"  ./moltbook deploy --direct")
        sys.exit(1)


def run_deploy(args):
    """Run the deploy command."""
    print(f"\n{CYAN}Deploying Moltbook Agent{RESET}\n")

    # Get custom config path if specified
    config_path = getattr(args, 'config', None)
    config_display = config_path or "agent_config.yaml"

    # Check for config (agent_config.yaml is preferred for direct mode)
    config = load_config()
    if not config:
        # Check if custom or default config exists
        check_path = Path(config_path) if config_path else Path("agent_config.yaml")
        if check_path.exists():
            config = {"agent": load_agent_config(config_path) or {}}
        else:
            print(f"{RED}✗{RESET} No configuration found: {config_display}")
            if not config_path:
                print(f"\nCreate agent_config.yaml:")
                print(f"  cp agent_config.template.yaml agent_config.yaml")
                print(f"  # Edit with your settings")
                print(f"  ./moltbook deploy")
            sys.exit(1)

    credentials = load_credentials()

    agent_name = config.get("agent", {}).get("name", "Unknown")
    archetype = getattr(args, 'archetype', None) or config.get("agent", {}).get("archetype", "custom")

    print(f"{BOLD}Config:{RESET}    {config_display}")
    print(f"{BOLD}Agent:{RESET}     {agent_name}")
    print(f"{BOLD}Archetype:{RESET} {archetype}")

    # Check for API keys (use unified loader with custom config)
    moltbook_api_key = get_api_key(config_path)
    has_moltbook_key = moltbook_api_key is not None
    has_llm_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")

    if not has_moltbook_key:
        print(f"\n{YELLOW}⚠{RESET} No Moltbook API key found.")
        print(f"Set MOLTBOOK_API_KEY environment variable or add to {config_display}")
        print("\nTo register an agent:")
        print(f"  curl -X POST https://www.moltbook.com/api/v1/agents/register \\")
        print(f"    -H 'Content-Type: application/json' \\")
        print(f"    -d '{{\"name\": \"{agent_name}\", \"description\": \"...\"}}'")
        sys.exit(1)

    if not has_llm_key:
        print(f"\n{YELLOW}⚠{RESET} No LLM API key found.")
        print("Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable")
        sys.exit(1)

    # Dry run check
    if hasattr(args, 'dry_run') and args.dry_run:
        mode = "Docker" if (hasattr(args, 'docker') and args.docker) else "direct"
        print(f"\n{YELLOW}[DRY RUN]{RESET} Would deploy with:")
        print(f"  - Mode: {mode}")
        print(f"  - Security: injection scanner enabled")
        print(f"  - Budget: ${config.get('security', {}).get('monthly_budget', 50.0):.2f}/month")
        return

    # Set budget if specified
    if hasattr(args, 'budget') and args.budget:
        config.setdefault("security", {})["monthly_budget"] = args.budget
        config_file = Path(".moltbook/config.json")
        if config_file.exists():
            with open(config_file, "w") as f:
                json.dump(config, f, indent=2)
        print(f"{GREEN}✓{RESET} Budget set to ${args.budget:.2f}/month")

    # Choose deployment mode (direct is default, Docker is optional)
    if hasattr(args, 'docker') and args.docker:
        run_docker_mode(config, credentials, args)
    else:
        run_direct_mode(config, credentials, config_path)
