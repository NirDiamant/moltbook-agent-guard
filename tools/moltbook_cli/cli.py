#!/usr/bin/env python3
"""
Moltbook CLI - Main entry point.

The security-first toolkit for building AI agents on Moltbook.
"""

import argparse
import sys
import os
from pathlib import Path

# ASCII art banner
BANNER = r"""
 __  __       _ _   _                 _
|  \/  | ___ | | |_| |__   ___   ___ | | __
| |\/| |/ _ \| | __| '_ \ / _ \ / _ \| |/ /
| |  | | (_) | | |_| |_) | (_) | (_) |   <
|_|  |_|\___/|_|\__|_.__/ \___/ \___/|_|\_\

        Agent Toolkit v0.1.0
        Security-first. Cost-aware. Observable.
"""

def print_banner():
    """Print the CLI banner."""
    print("\033[36m" + BANNER + "\033[0m")


def cmd_init(args):
    """Initialize a new Moltbook agent project."""
    from .commands.init import run_init
    run_init(args)


def cmd_deploy(args):
    """Deploy the agent to Moltbook."""
    from .commands.deploy import run_deploy
    run_deploy(args)


def cmd_status(args):
    """Check agent status."""
    from .commands.status import run_status
    run_status(args)


def cmd_claim(args):
    """Complete human verification."""
    from .commands.claim import run_claim
    run_claim(args)


def cmd_scan(args):
    """Scan for security threats."""
    from .commands.scan import run_scan
    run_scan(args)


def cmd_cost(args):
    """View cost estimates and usage."""
    from .commands.cost import run_cost
    run_cost(args)


def cmd_observatory(args):
    """Launch the monitoring dashboard."""
    from .commands.observatory import run_observatory
    run_observatory(args)


def cmd_security(args):
    """View security incidents and reports."""
    from .commands.security import run_security
    run_security(args)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Moltbook Agent Toolkit - Build secure AI agents for Moltbook",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  moltbook init                      # Interactive setup wizard
  moltbook init --archetype teacher  # Quick setup with Teacher archetype
  moltbook claim                     # Complete one-time verification
  moltbook deploy                    # Deploy your agent
  moltbook deploy --docker           # Deploy in Docker (optional)
  moltbook status                    # Check if agent is running
  moltbook scan                      # Scan recent posts for threats
  moltbook security                  # View security incidents (terminal)
  moltbook security --scan           # Scan Moltbook and record threats
  moltbook security --html report.html --open  # Generate & view HTML report
  moltbook cost estimate             # Estimate monthly costs
  moltbook observatory               # Launch monitoring dashboard

Documentation: https://github.com/NirDiamant/moltbook-agent-guard
        """
    )

    parser.add_argument(
        "--version", "-v",
        action="version",
        version="moltbook-agent 0.1.0"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # init command
    init_parser = subparsers.add_parser("init", help="Initialize a new agent project")
    init_parser.add_argument("--archetype", "-a",
                            choices=["teacher", "curator", "comedian", "philosopher", "researcher", "moderator"],
                            help="Use a pre-built archetype")
    init_parser.add_argument("--name", "-n", help="Agent name")
    init_parser.add_argument("--no-docker", action="store_true", help="Skip Docker setup (not recommended)")
    init_parser.add_argument("--dir", "-d", default=".", help="Project directory")
    init_parser.set_defaults(func=cmd_init)

    # deploy command
    deploy_parser = subparsers.add_parser("deploy", help="Deploy the agent")
    deploy_parser.add_argument("--config", "-c", help="Path to config file (default: agent_config.yaml)")
    deploy_parser.add_argument("--docker", action="store_true",
                               help="Run in Docker container (optional, for extra isolation)")
    deploy_parser.add_argument("--archetype", "-a", help="Override archetype for deployment")
    deploy_parser.add_argument("--dry-run", action="store_true", help="Show what would be deployed")
    deploy_parser.add_argument("--budget", "-b", type=float, help="Set monthly budget limit ($)")
    deploy_parser.set_defaults(func=cmd_deploy)

    # status command
    status_parser = subparsers.add_parser("status", help="Check agent status")
    status_parser.add_argument("--json", action="store_true", help="Output as JSON")
    status_parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed status")
    status_parser.set_defaults(func=cmd_status)

    # claim command
    claim_parser = subparsers.add_parser("claim", help="Complete human verification (one-time)")
    claim_parser.set_defaults(func=cmd_claim)

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for security threats")
    scan_parser.add_argument("--submolt", "-s", help="Scan specific submolt")
    scan_parser.add_argument("--posts", "-p", type=int, default=50, help="Number of posts to scan")
    scan_parser.add_argument("--output", "-o", help="Save report to file")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Show all matches")
    scan_parser.set_defaults(func=cmd_scan)

    # cost command
    cost_parser = subparsers.add_parser("cost", help="Cost management")
    cost_subparsers = cost_parser.add_subparsers(dest="cost_command")

    cost_estimate = cost_subparsers.add_parser("estimate", help="Estimate costs")
    cost_estimate.add_argument("--posts-per-day", type=int, default=5)
    cost_estimate.add_argument("--replies-per-day", type=int, default=20)
    cost_estimate.add_argument("--model", default="claude-3-5-sonnet")

    cost_usage = cost_subparsers.add_parser("usage", help="View current usage")
    cost_budget = cost_subparsers.add_parser("budget", help="Set budget limits")
    cost_budget.add_argument("--monthly", type=float, help="Monthly budget limit ($)")
    cost_budget.add_argument("--daily", type=float, help="Daily budget limit ($)")

    cost_parser.set_defaults(func=cmd_cost)

    # observatory command
    obs_parser = subparsers.add_parser("observatory", help="Launch monitoring dashboard")
    obs_parser.add_argument("--port", "-p", type=int, default=8080, help="Dashboard port")
    obs_parser.add_argument("--no-browser", action="store_true", help="Don't open browser")
    obs_parser.set_defaults(func=cmd_observatory)

    # security command
    sec_parser = subparsers.add_parser("security", help="View security incidents and reports")
    sec_parser.add_argument("--scan", action="store_true", help="Scan Moltbook for new threats")
    sec_parser.add_argument("--html", metavar="FILE", help="Generate HTML report to file")
    sec_parser.add_argument("--open", action="store_true", help="Open HTML report in browser")
    sec_parser.set_defaults(func=cmd_security)

    # Parse arguments
    args = parser.parse_args()

    if args.command is None:
        print_banner()
        parser.print_help()
        sys.exit(0)

    # Run the command
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n\nAborted.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\033[31mError: {e}\033[0m")
        sys.exit(1)


if __name__ == "__main__":
    main()
