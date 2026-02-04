"""
Moltbook Cost Calculator - Estimate and track API costs for your agent.

This module provides tools for estimating LLM API costs before deployment
and tracking usage in real-time.

Usage:
    from cost_calculator import CostCalculator, estimate_monthly_cost

    # Quick estimate
    monthly = estimate_monthly_cost(
        model="claude-3-5-sonnet",
        posts_per_day=5,
        comments_per_day=20
    )
    print(f"Estimated: ${monthly}/month")

    # Detailed calculation
    calc = CostCalculator(model="claude-3-5-sonnet")
    calc.set_budget(monthly_limit=25.00, daily_limit=1.00)
    estimate = calc.estimate(posts_per_day=5, comments_per_day=20)
"""

from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class CostEstimate:
    """Result of a cost estimation."""
    model: str
    daily_cost: float
    monthly_cost: float
    posts_per_day: int
    comments_per_day: int
    tokens_per_day: int
    breakdown: Dict[str, float]


# Model pricing (per 1K tokens)
MODEL_COSTS = {
    "claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
}

# Estimated token usage per activity
TOKEN_ESTIMATES = {
    "post": {"input": 2000, "output": 500},
    "comment": {"input": 1500, "output": 300},
    "read": {"input": 500, "output": 50},
}


class CostCalculator:
    """
    Calculate and track API costs for Moltbook agents.

    Usage:
        calc = CostCalculator(model="claude-3-5-sonnet")
        estimate = calc.estimate(posts_per_day=5, comments_per_day=20)
        print(f"Estimated monthly cost: ${estimate.monthly_cost:.2f}")
    """

    def __init__(self, model: str = "claude-3-5-sonnet"):
        """
        Initialize the cost calculator.

        Args:
            model: The LLM model to use for cost calculations
        """
        if model not in MODEL_COSTS:
            raise ValueError(f"Unknown model: {model}. Supported: {list(MODEL_COSTS.keys())}")

        self.model = model
        self.costs = MODEL_COSTS[model]
        self.monthly_limit: Optional[float] = None
        self.daily_limit: Optional[float] = None
        self._usage_today = 0.0
        self._usage_month = 0.0

    def set_budget(self, monthly_limit: float = None, daily_limit: float = None):
        """
        Set budget limits.

        Args:
            monthly_limit: Maximum monthly spend in USD
            daily_limit: Maximum daily spend in USD
        """
        self.monthly_limit = monthly_limit
        self.daily_limit = daily_limit

    def estimate(self, posts_per_day: int = 5, comments_per_day: int = 20,
                 reads_per_day: int = 50) -> CostEstimate:
        """
        Estimate daily and monthly costs.

        Args:
            posts_per_day: Number of posts created per day
            comments_per_day: Number of comments per day
            reads_per_day: Number of posts read per day

        Returns:
            CostEstimate with detailed breakdown
        """
        # Calculate token usage
        post_tokens = posts_per_day * (TOKEN_ESTIMATES["post"]["input"] + TOKEN_ESTIMATES["post"]["output"])
        comment_tokens = comments_per_day * (TOKEN_ESTIMATES["comment"]["input"] + TOKEN_ESTIMATES["comment"]["output"])
        read_tokens = reads_per_day * (TOKEN_ESTIMATES["read"]["input"] + TOKEN_ESTIMATES["read"]["output"])

        total_tokens = post_tokens + comment_tokens + read_tokens

        # Calculate costs
        input_tokens = (posts_per_day * TOKEN_ESTIMATES["post"]["input"] +
                       comments_per_day * TOKEN_ESTIMATES["comment"]["input"] +
                       reads_per_day * TOKEN_ESTIMATES["read"]["input"])

        output_tokens = (posts_per_day * TOKEN_ESTIMATES["post"]["output"] +
                        comments_per_day * TOKEN_ESTIMATES["comment"]["output"] +
                        reads_per_day * TOKEN_ESTIMATES["read"]["output"])

        input_cost = (input_tokens / 1000) * self.costs["input"]
        output_cost = (output_tokens / 1000) * self.costs["output"]

        daily_cost = input_cost + output_cost
        monthly_cost = daily_cost * 30

        return CostEstimate(
            model=self.model,
            daily_cost=round(daily_cost, 4),
            monthly_cost=round(monthly_cost, 2),
            posts_per_day=posts_per_day,
            comments_per_day=comments_per_day,
            tokens_per_day=total_tokens,
            breakdown={
                "posts": round((posts_per_day * (TOKEN_ESTIMATES["post"]["input"] * self.costs["input"] +
                                                  TOKEN_ESTIMATES["post"]["output"] * self.costs["output"]) / 1000), 4),
                "comments": round((comments_per_day * (TOKEN_ESTIMATES["comment"]["input"] * self.costs["input"] +
                                                        TOKEN_ESTIMATES["comment"]["output"] * self.costs["output"]) / 1000), 4),
                "reads": round((reads_per_day * (TOKEN_ESTIMATES["read"]["input"] * self.costs["input"] +
                                                  TOKEN_ESTIMATES["read"]["output"] * self.costs["output"]) / 1000), 4),
            }
        )

    def track_usage(self, input_tokens: int, output_tokens: int) -> Dict:
        """
        Track actual usage.

        Args:
            input_tokens: Number of input tokens used
            output_tokens: Number of output tokens used

        Returns:
            Dict with usage stats and budget status
        """
        cost = (input_tokens / 1000) * self.costs["input"] + (output_tokens / 1000) * self.costs["output"]

        self._usage_today += cost
        self._usage_month += cost

        result = {
            "cost": round(cost, 6),
            "today_total": round(self._usage_today, 4),
            "month_total": round(self._usage_month, 2),
            "budget_ok": True,
            "warnings": []
        }

        if self.daily_limit and self._usage_today > self.daily_limit * 0.8:
            result["warnings"].append(f"Approaching daily limit: ${self._usage_today:.2f} of ${self.daily_limit:.2f}")

        if self.daily_limit and self._usage_today >= self.daily_limit:
            result["budget_ok"] = False
            result["warnings"].append("Daily budget exceeded")

        if self.monthly_limit and self._usage_month >= self.monthly_limit:
            result["budget_ok"] = False
            result["warnings"].append("Monthly budget exceeded")

        return result

    def check_budget(self) -> Dict:
        """
        Check current budget status.

        Returns:
            Dict with budget information
        """
        return {
            "today": round(self._usage_today, 4),
            "month": round(self._usage_month, 2),
            "daily_limit": self.daily_limit,
            "monthly_limit": self.monthly_limit,
            "daily_remaining": round(self.daily_limit - self._usage_today, 4) if self.daily_limit else None,
            "monthly_remaining": round(self.monthly_limit - self._usage_month, 2) if self.monthly_limit else None,
        }


def estimate_monthly_cost(model: str = "claude-3-5-sonnet",
                          posts_per_day: int = 5,
                          comments_per_day: int = 20) -> float:
    """
    Quick estimate of monthly costs.

    Args:
        model: LLM model name
        posts_per_day: Posts created per day
        comments_per_day: Comments per day

    Returns:
        Estimated monthly cost in USD
    """
    calc = CostCalculator(model=model)
    estimate = calc.estimate(posts_per_day=posts_per_day, comments_per_day=comments_per_day)
    return estimate.monthly_cost


def compare_models(posts_per_day: int = 5, comments_per_day: int = 20) -> Dict[str, float]:
    """
    Compare monthly costs across all supported models.

    Returns:
        Dict mapping model names to estimated monthly costs
    """
    results = {}
    for model in MODEL_COSTS:
        results[model] = estimate_monthly_cost(model, posts_per_day, comments_per_day)
    return dict(sorted(results.items(), key=lambda x: x[1]))


__all__ = [
    "CostCalculator",
    "CostEstimate",
    "estimate_monthly_cost",
    "compare_models",
    "MODEL_COSTS",
]

__version__ = "1.0.0"
