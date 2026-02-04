"""
Financial Safety - Prevent unauthorized purchases and financial actions.

Threats addressed:
- Tricking agent into making purchases
- Unauthorized API calls that cost money
- Signing up for paid services
- Approving transactions
- Subscription traps
- Crypto/payment scams

This module detects and blocks financial threats.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)


@dataclass
class FinancialCheckResult:
    """Result of financial safety check."""
    is_safe: bool
    risk_level: str  # "none", "low", "medium", "high", "critical"
    threats_detected: List[str]
    requires_approval: bool
    recommendations: List[str]


@dataclass
class SpendingRecord:
    """Record of spending/cost."""
    timestamp: str
    action: str
    estimated_cost: float
    approved: bool
    details: str


class FinancialSafety:
    """
    Detect and prevent unauthorized financial actions.

    Protects against:
    - Purchase requests
    - Paid service signups
    - Expensive API calls
    - Transaction approvals
    - Crypto/payment scams

    Usage:
        safety = FinancialSafety(daily_limit=10.0)

        # Before taking any action
        result = safety.check_action(action_description)
        if result.requires_approval:
            # Ask user for explicit approval

        # Check incoming requests
        result = safety.check_request(message)
        if not result.is_safe:
            # Refuse financial action
    """

    # Patterns indicating financial requests
    FINANCIAL_PATTERNS = [
        # Direct purchase requests
        (r"\b(buy|purchase|order|acquire|get me)\b.*\$\s*\d+",
         "purchase_request", "critical"),
        (r"\b(buy|purchase|order|acquire|get me)\b.*\b(subscription|plan|service|product)\b",
         "purchase_request2", "critical"),
        (r"\b(add to cart|checkout|complete.*(order|purchase)|place.*(order|bid))\b",
         "checkout_attempt", "critical"),

        # Payment/transfer requests
        (r"\b(send|transfer|pay|wire)\b.*\b(money|\$|dollars|euros|funds)\b",
         "money_transfer", "critical"),
        (r"\b(venmo|paypal|zelle|cash ?app|wise|western union)\b",
         "payment_service", "high"),

        # Subscription/signup attempts
        (r"\b(sign ?up|subscribe|register|create account)\b.*\b(paid|premium|pro|plus)\b",
         "paid_signup", "high"),
        (r"\b(free trial|start trial)\b",
         "trial_signup", "medium"),
        (r"\b(upgrade|unlock|activate)\b.*\b(premium|pro|full|paid)\b",
         "upgrade_request", "high"),

        # Crypto-related (high scam risk)
        (r"\b(bitcoin|btc|ethereum|eth|crypto|wallet|seed ?phrase|private key)\b",
         "crypto_mention", "high"),
        (r"\b(send|transfer)\b.*\b(btc|eth|crypto|coin)\b",
         "crypto_transfer", "critical"),
        (r"\b(connect|link).*(wallet|metamask)\b",
         "wallet_connect", "critical"),

        # Investment/trading
        (r"\b(invest|trade|buy|sell)\b.*\b(stock|share|option|future|forex)\b",
         "trading_request", "critical"),
        (r"\b(deposit|withdraw)\b.*\b(funds|money|\$)\b",
         "deposit_withdraw", "critical"),

        # API cost triggers
        (r"\b(call|use|invoke)\b.*\b(api|endpoint)\b.*\b(times|iterations|loop)\b",
         "bulk_api_call", "medium"),
        (r"\b(generate|create)\b.*\b(\d{3,}|hundreds|thousands)\b.*\b(images?|videos?|files?)\b",
         "expensive_generation", "high"),

        # Contract/agreement
        (r"\b(agree|accept|sign|approve)\b.*\b(terms|contract|agreement|tos)\b",
         "agreement_signing", "high"),
        (r"\b(confirm|authorize|approve)\b.*\b(payment|charge|transaction|purchase)\b",
         "transaction_approval", "critical"),

        # Gift cards (common scam)
        (r"\b(gift ?cards?|prepaid ?cards?|store ?credits?)\b",
         "gift_card", "high"),
        (r"\b(redeem|activate)\b.*\b(code|voucher|coupon)\b",
         "code_redemption", "medium"),
    ]

    # URLs that indicate financial/payment sites
    FINANCIAL_DOMAINS = [
        r"paypal\.com", r"stripe\.com", r"square\.com",
        r"venmo\.com", r"cash\.app", r"zelle\.com",
        r"wise\.com", r"westernunion\.com",
        r"coinbase\.com", r"binance\.com", r"kraken\.com",
        r"robinhood\.com", r"etrade\.com", r"fidelity\.com",
        r"checkout\.", r"pay\.", r"payment\.",
        r"shop\.", r"store\.", r"buy\.",
    ]

    # Actions that always require approval
    APPROVAL_REQUIRED = [
        "purchase_request", "checkout_attempt", "money_transfer",
        "crypto_transfer", "trading_request", "deposit_withdraw",
        "transaction_approval", "wallet_connect",
    ]

    def __init__(self,
                 daily_limit: float = 0.0,
                 require_approval_above: float = 0.0,
                 block_all_financial: bool = True,
                 data_file: str = None):
        """
        Initialize financial safety.

        Args:
            daily_limit: Maximum daily spending (0 = no spending allowed)
            require_approval_above: Require approval for amounts above this
            block_all_financial: If True, block ALL financial actions
            data_file: Path to store spending records
        """
        self.daily_limit = daily_limit
        self.require_approval_above = require_approval_above
        self.block_all_financial = block_all_financial

        self.data_file = Path(data_file or ".moltbook/financial_safety.json")
        self.data_file.parent.mkdir(parents=True, exist_ok=True)

        # Compile patterns
        self._patterns = [(re.compile(p, re.IGNORECASE), name, risk)
                         for p, name, risk in self.FINANCIAL_PATTERNS]
        self._domains = [re.compile(d, re.IGNORECASE) for d in self.FINANCIAL_DOMAINS]

        self._spending: List[SpendingRecord] = []
        self._load_data()

    def _load_data(self):
        """Load spending records from disk."""
        if not self.data_file.exists():
            return

        try:
            with open(self.data_file) as f:
                data = json.load(f)
                self._spending = [
                    SpendingRecord(**r) for r in data.get("spending", [])
                ]
        except Exception as e:
            logger.warning(f"Failed to load financial data: {e}")

    def _save_data(self):
        """Save spending records to disk."""
        try:
            # Keep only last 30 days
            cutoff = (datetime.utcnow() - timedelta(days=30)).isoformat()
            recent = [s for s in self._spending if s.timestamp > cutoff]

            data = {
                "spending": [
                    {
                        "timestamp": s.timestamp,
                        "action": s.action,
                        "estimated_cost": s.estimated_cost,
                        "approved": s.approved,
                        "details": s.details,
                    }
                    for s in recent
                ]
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save financial data: {e}")

    def check_request(self, content: str) -> FinancialCheckResult:
        """
        Check if a request involves financial actions.

        Args:
            content: Incoming message/request

        Returns:
            FinancialCheckResult
        """
        threats = []
        risk_scores = []
        requires_approval = False

        # Check financial patterns
        for pattern, name, risk in self._patterns:
            if pattern.search(content):
                threats.append(name)
                risk_scores.append(
                    {"critical": 4, "high": 3, "medium": 2, "low": 1}[risk]
                )
                if name in self.APPROVAL_REQUIRED:
                    requires_approval = True

        # Check for financial URLs
        for domain in self._domains:
            if domain.search(content):
                threats.append("financial_url")
                risk_scores.append(3)
                break

        # Extract any mentioned amounts
        amount = self._extract_amount(content)
        if amount and amount > self.require_approval_above:
            requires_approval = True

        # Determine overall risk
        if not threats:
            return FinancialCheckResult(
                is_safe=True,
                risk_level="none",
                threats_detected=[],
                requires_approval=False,
                recommendations=[]
            )

        max_risk = max(risk_scores)
        if max_risk >= 4:
            risk_level = "critical"
        elif max_risk >= 3:
            risk_level = "high"
        elif max_risk >= 2:
            risk_level = "medium"
        else:
            risk_level = "low"

        # Generate recommendations
        recommendations = []
        if self.block_all_financial:
            recommendations.append("Financial actions are blocked for this agent")
            is_safe = False
        elif requires_approval:
            recommendations.append("This action requires explicit user approval")
            is_safe = False
        elif risk_level in ["critical", "high"]:
            recommendations.append("Exercise extreme caution with financial requests")
            is_safe = False
        else:
            recommendations.append("Monitor this interaction for financial manipulation")
            is_safe = True

        if "crypto" in str(threats):
            recommendations.append("Crypto requests are high-risk for scams")
        if "gift_card" in threats:
            recommendations.append("Gift card requests are a common scam tactic")

        return FinancialCheckResult(
            is_safe=is_safe,
            risk_level=risk_level,
            threats_detected=threats,
            requires_approval=requires_approval,
            recommendations=recommendations
        )

    def check_url(self, url: str) -> FinancialCheckResult:
        """
        Check if a URL is a financial/payment site.

        Args:
            url: URL to check

        Returns:
            FinancialCheckResult
        """
        for domain in self._domains:
            if domain.search(url):
                return FinancialCheckResult(
                    is_safe=False,
                    risk_level="high",
                    threats_detected=["financial_url"],
                    requires_approval=True,
                    recommendations=[
                        "This appears to be a financial/payment site",
                        "Do not interact without explicit user approval"
                    ]
                )

        return FinancialCheckResult(
            is_safe=True,
            risk_level="none",
            threats_detected=[],
            requires_approval=False,
            recommendations=[]
        )

    def _extract_amount(self, content: str) -> Optional[float]:
        """Extract monetary amount from content."""
        patterns = [
            r"\$\s*([\d,]+(?:\.\d{2})?)",  # $100 or $100.00
            r"([\d,]+(?:\.\d{2})?)\s*(?:dollars?|usd)",  # 100 dollars
            r"([\d,]+(?:\.\d{2})?)\s*(?:euros?|eur)",  # 100 euros
        ]

        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                try:
                    return float(match.group(1).replace(",", ""))
                except ValueError:
                    pass

        return None

    def get_daily_spending(self) -> float:
        """Get total spending for today."""
        today = datetime.utcnow().date().isoformat()
        return sum(
            s.estimated_cost for s in self._spending
            if s.timestamp.startswith(today) and s.approved
        )

    def record_spending(self, action: str, cost: float, approved: bool, details: str = ""):
        """Record a spending/cost event."""
        record = SpendingRecord(
            timestamp=datetime.utcnow().isoformat(),
            action=action,
            estimated_cost=cost,
            approved=approved,
            details=details
        )
        self._spending.append(record)
        self._save_data()

        if approved:
            logger.info(f"Approved financial action: {action} (${cost:.2f})")
        else:
            logger.warning(f"Blocked financial action: {action} (${cost:.2f})")

    def can_spend(self, amount: float) -> bool:
        """Check if spending amount is within limits."""
        if self.block_all_financial:
            return False
        if self.daily_limit <= 0:
            return False
        return self.get_daily_spending() + amount <= self.daily_limit

    def get_stats(self) -> Dict:
        """Get financial safety statistics."""
        today = datetime.utcnow().date().isoformat()
        today_records = [s for s in self._spending if s.timestamp.startswith(today)]

        return {
            "daily_limit": self.daily_limit,
            "daily_spent": self.get_daily_spending(),
            "daily_remaining": max(0, self.daily_limit - self.get_daily_spending()),
            "today_blocked": sum(1 for s in today_records if not s.approved),
            "today_approved": sum(1 for s in today_records if s.approved),
            "total_blocked": sum(1 for s in self._spending if not s.approved),
            "block_all_financial": self.block_all_financial,
        }


# Global instance
_financial_safety: Optional[FinancialSafety] = None


def get_financial_safety() -> FinancialSafety:
    """Get or create the global financial safety."""
    global _financial_safety
    if _financial_safety is None:
        _financial_safety = FinancialSafety()
    return _financial_safety


def check_financial_request(content: str) -> FinancialCheckResult:
    """Check if content involves financial actions."""
    return get_financial_safety().check_request(content)


def is_financial_safe(content: str) -> bool:
    """Quick check if content is financially safe."""
    result = get_financial_safety().check_request(content)
    return result.is_safe


def block_all_financial_actions():
    """Configure to block all financial actions (safest mode)."""
    global _financial_safety
    _financial_safety = FinancialSafety(
        daily_limit=0.0,
        block_all_financial=True
    )
