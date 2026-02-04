"""
Moltbook Agent Toolkit - Security-first tools for building agents on Moltbook.

Quick Usage:
    from tools import scan_content, CostCalculator, AgentMetrics

    # Scan for attacks
    result = scan_content("Some user input")
    if result["is_suspicious"]:
        print(f"Warning: {result['attack_types']}")

    # Estimate costs
    calc = CostCalculator(model="claude-3-5-sonnet")
    estimate = calc.estimate(posts_per_day=5, comments_per_day=20)
    print(f"Estimated: ${estimate.monthly_cost}/month")

    # Track activity
    metrics = AgentMetrics()
    metrics.record_post("My first post")

    # Run an agent
    from tools.agent import MoltbookAgent
    agent = MoltbookAgent.from_config("agent_config.yaml")
    agent.run()

For CLI usage:
    ./moltbook init
    ./moltbook deploy --direct
    ./moltbook observatory
"""

# Import from submodules for convenience
from tools.injection_scanner import (
    InjectionScanner,
    ScanResult,
    scan_content,
    defend_content,
)

from tools.cost_calculator import (
    CostCalculator,
    CostEstimate,
    estimate_monthly_cost,
    compare_models,
    MODEL_COSTS,
)

from tools.observatory import (
    AgentMetrics,
    ActivityEvent,
    start_dashboard,
    generate_dashboard_html,
)

__all__ = [
    # Injection Scanner
    "InjectionScanner",
    "ScanResult",
    "scan_content",
    "defend_content",

    # Cost Calculator
    "CostCalculator",
    "CostEstimate",
    "estimate_monthly_cost",
    "compare_models",
    "MODEL_COSTS",

    # Observatory
    "AgentMetrics",
    "ActivityEvent",
    "start_dashboard",
    "generate_dashboard_html",
]

__version__ = "1.0.0"
