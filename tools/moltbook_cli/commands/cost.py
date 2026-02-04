"""
moltbook cost - Cost estimation and budget management.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
RESET = "\033[0m"

# Approximate token costs (per 1M tokens, as of 2026)
MODEL_COSTS = {
    "claude-3-5-sonnet": {"input": 3.00, "output": 15.00},
    "claude-3-opus": {"input": 15.00, "output": 75.00},
    "claude-3-haiku": {"input": 0.25, "output": 1.25},
    "gpt-4o": {"input": 2.50, "output": 10.00},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4-turbo": {"input": 10.00, "output": 30.00},
}

# Average tokens per interaction
AVG_TOKENS = {
    "post_read": 500,      # Reading a post
    "post_write": 300,     # Writing a post
    "comment_read": 200,   # Reading comments
    "comment_write": 150,  # Writing a comment
    "system_prompt": 1000, # System prompt overhead
}


def load_config():
    """Load project configuration."""
    config_file = Path(".moltbook/config.json")
    if not config_file.exists():
        return None
    with open(config_file) as f:
        return json.load(f)


def save_config(config):
    """Save configuration."""
    with open(".moltbook/config.json", "w") as f:
        json.dump(config, f, indent=2)


def estimate_costs(posts_per_day, replies_per_day, model):
    """Estimate monthly costs."""
    if model not in MODEL_COSTS:
        model = "claude-3-5-sonnet"

    costs = MODEL_COSTS[model]

    # Daily token usage estimate
    daily_input_tokens = (
        posts_per_day * (AVG_TOKENS["post_read"] + AVG_TOKENS["system_prompt"]) +
        replies_per_day * (AVG_TOKENS["comment_read"] + AVG_TOKENS["system_prompt"])
    )

    daily_output_tokens = (
        posts_per_day * AVG_TOKENS["post_write"] +
        replies_per_day * AVG_TOKENS["comment_write"]
    )

    # Calculate costs
    daily_input_cost = (daily_input_tokens / 1_000_000) * costs["input"]
    daily_output_cost = (daily_output_tokens / 1_000_000) * costs["output"]
    daily_total = daily_input_cost + daily_output_cost

    return {
        "model": model,
        "daily": {
            "input_tokens": daily_input_tokens,
            "output_tokens": daily_output_tokens,
            "input_cost": daily_input_cost,
            "output_cost": daily_output_cost,
            "total": daily_total,
        },
        "monthly": {
            "input_tokens": daily_input_tokens * 30,
            "output_tokens": daily_output_tokens * 30,
            "input_cost": daily_input_cost * 30,
            "output_cost": daily_output_cost * 30,
            "total": daily_total * 30,
        }
    }


def run_cost(args):
    """Run the cost command."""
    config = load_config()

    if args.cost_command == "estimate":
        print(f"\n{CYAN}{'='*50}{RESET}")
        print(f"{BOLD}  Cost Estimate{RESET}")
        print(f"{CYAN}{'='*50}{RESET}\n")

        model = args.model if hasattr(args, 'model') else "claude-3-5-sonnet"
        posts = args.posts_per_day if hasattr(args, 'posts_per_day') else 5
        replies = args.replies_per_day if hasattr(args, 'replies_per_day') else 20

        estimate = estimate_costs(posts, replies, model)

        print(f"{BOLD}Parameters:{RESET}")
        print(f"  Model:           {estimate['model']}")
        print(f"  Posts/day:       {posts}")
        print(f"  Replies/day:     {replies}")

        print(f"\n{BOLD}Daily Estimate:{RESET}")
        print(f"  Input tokens:    {estimate['daily']['input_tokens']:,}")
        print(f"  Output tokens:   {estimate['daily']['output_tokens']:,}")
        print(f"  Input cost:      ${estimate['daily']['input_cost']:.4f}")
        print(f"  Output cost:     ${estimate['daily']['output_cost']:.4f}")
        print(f"  {BOLD}Total:{RESET}           ${estimate['daily']['total']:.4f}")

        print(f"\n{BOLD}Monthly Estimate:{RESET}")
        print(f"  Input tokens:    {estimate['monthly']['input_tokens']:,}")
        print(f"  Output tokens:   {estimate['monthly']['output_tokens']:,}")
        print(f"  Input cost:      ${estimate['monthly']['input_cost']:.2f}")
        print(f"  Output cost:     ${estimate['monthly']['output_cost']:.2f}")
        print(f"  {BOLD}Total:{RESET}           {CYAN}${estimate['monthly']['total']:.2f}{RESET}")

        # Comparison table
        print(f"\n{BOLD}Cost Comparison by Model:{RESET}\n")
        print(f"  {'Model':<20} {'Monthly Cost':>12}")
        print(f"  {'-'*20} {'-'*12}")
        for m in sorted(MODEL_COSTS.keys()):
            est = estimate_costs(posts, replies, m)
            marker = " ◀" if m == model else ""
            print(f"  {m:<20} ${est['monthly']['total']:>10.2f}{marker}")

        # Budget warning
        if config:
            budget = config.get("security", {}).get("monthly_budget", 50.0)
            if estimate["monthly"]["total"] > budget:
                print(f"\n{RED}⚠ WARNING: Estimated cost exceeds budget (${budget:.2f}){RESET}")
                print(f"  Consider reducing activity or using a cheaper model.")
            else:
                print(f"\n{GREEN}✓ Within budget (${budget:.2f}){RESET}")

    elif args.cost_command == "usage":
        print(f"\n{CYAN}{'='*50}{RESET}")
        print(f"{BOLD}  Usage Tracking{RESET}")
        print(f"{CYAN}{'='*50}{RESET}\n")

        # Check for usage log
        usage_file = Path(".moltbook/usage.json")
        if usage_file.exists():
            with open(usage_file) as f:
                usage = json.load(f)
            print(f"  Period:          {usage.get('period', 'Unknown')}")
            print(f"  Input tokens:    {usage.get('input_tokens', 0):,}")
            print(f"  Output tokens:   {usage.get('output_tokens', 0):,}")
            print(f"  Estimated cost:  ${usage.get('estimated_cost', 0):.2f}")
            print(f"  Posts created:   {usage.get('posts', 0)}")
            print(f"  Comments:        {usage.get('comments', 0)}")
        else:
            print(f"  {YELLOW}No usage data yet.{RESET}")
            print(f"  Usage tracking starts when your agent is deployed.")

    elif args.cost_command == "budget":
        if not config:
            print(f"{RED}✗{RESET} No configuration found. Run 'moltbook init' first.")
            sys.exit(1)

        print(f"\n{CYAN}{'='*50}{RESET}")
        print(f"{BOLD}  Budget Settings{RESET}")
        print(f"{CYAN}{'='*50}{RESET}\n")

        config.setdefault("security", {})

        if hasattr(args, 'monthly') and args.monthly:
            config["security"]["monthly_budget"] = args.monthly
            config["security"]["budget_enabled"] = True
            save_config(config)
            print(f"{GREEN}✓{RESET} Monthly budget set to ${args.monthly:.2f}")

        if hasattr(args, 'daily') and args.daily:
            config["security"]["daily_budget"] = args.daily
            config["security"]["budget_enabled"] = True
            save_config(config)
            print(f"{GREEN}✓{RESET} Daily budget set to ${args.daily:.2f}")

        # Show current settings
        print(f"\n{BOLD}Current Budget Settings:{RESET}")
        print(f"  Enabled:  {GREEN if config['security'].get('budget_enabled') else YELLOW}{'Yes' if config['security'].get('budget_enabled') else 'No'}{RESET}")
        print(f"  Monthly:  ${config['security'].get('monthly_budget', 50.0):.2f}")
        print(f"  Daily:    ${config['security'].get('daily_budget', 5.0):.2f}")

        print(f"\n{BOLD}Actions when limit reached:{RESET}")
        print(f"  - Agent activity paused")
        print(f"  - Alert sent to observatory")
        print(f"  - Manual restart required")

    else:
        # Default: show summary
        print(f"\n{CYAN}Cost Management{RESET}\n")
        print(f"Commands:")
        print(f"  moltbook cost estimate  - Estimate monthly costs")
        print(f"  moltbook cost usage     - View current usage")
        print(f"  moltbook cost budget    - Set budget limits")
        print(f"\nOptions for estimate:")
        print(f"  --posts-per-day N       - Expected posts per day")
        print(f"  --replies-per-day N     - Expected replies per day")
        print(f"  --model MODEL           - Model to estimate for")

    print()
