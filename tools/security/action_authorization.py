"""
Action Authorization - Require explicit approval for sensitive actions.

Threats addressed:
- Agent taking unauthorized actions on behalf of user
- Tricking agent into destructive operations
- Unauthorized account changes
- Sending messages without consent
- Making commitments on user's behalf

This module ensures sensitive actions require explicit user approval.
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ActionCategory(Enum):
    """Categories of actions that may need authorization."""
    FINANCIAL = "financial"
    ACCOUNT = "account"
    COMMUNICATION = "communication"
    DATA = "data"
    SYSTEM = "system"
    EXTERNAL = "external"
    COMMITMENT = "commitment"


@dataclass
class AuthorizationRequest:
    """A request for action authorization."""
    action_id: str
    category: ActionCategory
    action: str
    description: str
    risk_level: str
    timestamp: str
    context: Dict
    approved: Optional[bool] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None


@dataclass
class AuthorizationResult:
    """Result of authorization check."""
    requires_approval: bool
    is_approved: bool
    action_id: Optional[str]
    category: Optional[ActionCategory]
    reason: str
    auto_approved: bool


class ActionAuthorization:
    """
    Manage authorization for sensitive agent actions.

    Requires approval for:
    - Financial transactions
    - Account modifications
    - Sending messages as user
    - Sharing personal data
    - Making commitments
    - External service interactions

    Usage:
        auth = ActionAuthorization()

        # Before taking action
        result = auth.check_action("send_dm", "Send DM to @user")
        if result.requires_approval and not result.is_approved:
            # Request user approval
            auth.request_approval(result.action_id, context)
            return "I need your approval to send this message"

        # After user approves
        auth.approve(action_id, "user")
    """

    # Actions that always require approval
    SENSITIVE_ACTIONS = {
        # Financial
        "purchase": (ActionCategory.FINANCIAL, "high"),
        "subscribe": (ActionCategory.FINANCIAL, "high"),
        "payment": (ActionCategory.FINANCIAL, "critical"),
        "transfer": (ActionCategory.FINANCIAL, "critical"),

        # Account
        "change_password": (ActionCategory.ACCOUNT, "critical"),
        "change_email": (ActionCategory.ACCOUNT, "critical"),
        "delete_account": (ActionCategory.ACCOUNT, "critical"),
        "update_profile": (ActionCategory.ACCOUNT, "medium"),
        "change_settings": (ActionCategory.ACCOUNT, "medium"),
        "connect_service": (ActionCategory.ACCOUNT, "high"),

        # Communication
        "send_dm": (ActionCategory.COMMUNICATION, "medium"),
        "send_email": (ActionCategory.COMMUNICATION, "high"),
        "post_public": (ActionCategory.COMMUNICATION, "low"),
        "reply_public": (ActionCategory.COMMUNICATION, "low"),
        "mention_user": (ActionCategory.COMMUNICATION, "medium"),

        # Data
        "share_file": (ActionCategory.DATA, "high"),
        "export_data": (ActionCategory.DATA, "high"),
        "delete_data": (ActionCategory.DATA, "critical"),
        "share_contact": (ActionCategory.DATA, "high"),
        "share_location": (ActionCategory.DATA, "critical"),

        # System
        "install_skill": (ActionCategory.SYSTEM, "high"),
        "execute_code": (ActionCategory.SYSTEM, "critical"),
        "modify_config": (ActionCategory.SYSTEM, "high"),
        "grant_permission": (ActionCategory.SYSTEM, "critical"),

        # External
        "api_call": (ActionCategory.EXTERNAL, "low"),
        "webhook_send": (ActionCategory.EXTERNAL, "medium"),
        "oauth_authorize": (ActionCategory.EXTERNAL, "high"),
        "download_file": (ActionCategory.EXTERNAL, "medium"),

        # Commitments
        "schedule_meeting": (ActionCategory.COMMITMENT, "medium"),
        "make_promise": (ActionCategory.COMMITMENT, "medium"),
        "agree_terms": (ActionCategory.COMMITMENT, "high"),
        "sign_document": (ActionCategory.COMMITMENT, "critical"),
    }

    # Patterns in content that indicate sensitive actions
    ACTION_PATTERNS = [
        (r"\b(send|post|share|publish)\b.*\b(message|dm|email|tweet)\b",
         "send_message", ActionCategory.COMMUNICATION),
        (r"\b(change|update|modify|edit)\b.*\b(password|email|profile|settings)\b",
         "account_change", ActionCategory.ACCOUNT),
        (r"\b(delete|remove|erase)\b.*\b(account|data|file|message)\b",
         "delete_action", ActionCategory.DATA),
        (r"\b(agree|accept|sign|confirm)\b.*\b(terms|contract|agreement)\b",
         "agreement", ActionCategory.COMMITMENT),
        (r"\b(install|add|enable)\b.*\b(plugin|skill|extension|app)\b",
         "install_action", ActionCategory.SYSTEM),
        (r"\b(connect|link|authorize)\b.*\b(account|service|app)\b",
         "connect_service", ActionCategory.EXTERNAL),
        (r"\b(schedule|book|reserve)\b.*\b(meeting|appointment|call)\b",
         "schedule_action", ActionCategory.COMMITMENT),
        (r"\b(share|send|give)\b.*\b(location|address|phone|email)\b",
         "share_pii", ActionCategory.DATA),
    ]

    def __init__(self,
                 auto_approve_low_risk: bool = False,
                 require_approval_for: List[ActionCategory] = None,
                 data_file: str = None):
        """
        Initialize action authorization.

        Args:
            auto_approve_low_risk: Auto-approve low-risk actions
            require_approval_for: Categories requiring approval (default: all)
            data_file: Path to store authorization data
        """
        self.auto_approve_low_risk = auto_approve_low_risk
        self.require_approval_for = require_approval_for or list(ActionCategory)

        self.data_file = Path(data_file or ".moltbook/action_auth.json")
        self.data_file.parent.mkdir(parents=True, exist_ok=True)

        # Compile patterns
        self._patterns = [(re.compile(p, re.IGNORECASE), action, category)
                         for p, action, category in self.ACTION_PATTERNS]

        self._pending: Dict[str, AuthorizationRequest] = {}
        self._history: List[AuthorizationRequest] = []
        self._load_data()

    def _load_data(self):
        """Load authorization data from disk."""
        if not self.data_file.exists():
            return

        try:
            with open(self.data_file) as f:
                data = json.load(f)
                self._pending = {
                    k: AuthorizationRequest(
                        action_id=v["action_id"],
                        category=ActionCategory(v["category"]),
                        action=v["action"],
                        description=v["description"],
                        risk_level=v["risk_level"],
                        timestamp=v["timestamp"],
                        context=v["context"],
                        approved=v.get("approved"),
                        approved_by=v.get("approved_by"),
                        approved_at=v.get("approved_at"),
                    )
                    for k, v in data.get("pending", {}).items()
                }
        except Exception as e:
            logger.warning(f"Failed to load authorization data: {e}")

    def _save_data(self):
        """Save authorization data to disk."""
        try:
            data = {
                "pending": {
                    k: {
                        "action_id": v.action_id,
                        "category": v.category.value,
                        "action": v.action,
                        "description": v.description,
                        "risk_level": v.risk_level,
                        "timestamp": v.timestamp,
                        "context": v.context,
                        "approved": v.approved,
                        "approved_by": v.approved_by,
                        "approved_at": v.approved_at,
                    }
                    for k, v in self._pending.items()
                }
            }
            with open(self.data_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save authorization data: {e}")

    def _generate_action_id(self) -> str:
        """Generate unique action ID."""
        import hashlib
        import time
        data = f"{time.time()}-{id(self)}"
        return hashlib.sha256(data.encode()).hexdigest()[:12]

    def check_action(self, action: str, description: str = "",
                    context: Dict = None) -> AuthorizationResult:
        """
        Check if an action requires authorization.

        Args:
            action: Action name (e.g., "send_dm", "purchase")
            description: Human-readable description
            context: Additional context

        Returns:
            AuthorizationResult
        """
        context = context or {}

        # Check if this is a known sensitive action
        if action in self.SENSITIVE_ACTIONS:
            category, risk_level = self.SENSITIVE_ACTIONS[action]
        else:
            # Try to detect from description
            category, risk_level = self._detect_action_type(description)

        # Check if this category requires approval
        if category and category in self.require_approval_for:
            # Check if low-risk can be auto-approved
            if self.auto_approve_low_risk and risk_level == "low":
                return AuthorizationResult(
                    requires_approval=False,
                    is_approved=True,
                    action_id=None,
                    category=category,
                    reason="Auto-approved (low risk)",
                    auto_approved=True
                )

            # Create authorization request
            action_id = self._generate_action_id()
            request = AuthorizationRequest(
                action_id=action_id,
                category=category,
                action=action,
                description=description,
                risk_level=risk_level or "medium",
                timestamp=datetime.utcnow().isoformat(),
                context=context
            )
            self._pending[action_id] = request
            self._save_data()

            return AuthorizationResult(
                requires_approval=True,
                is_approved=False,
                action_id=action_id,
                category=category,
                reason=f"Action '{action}' requires user approval",
                auto_approved=False
            )

        # Action doesn't require approval
        return AuthorizationResult(
            requires_approval=False,
            is_approved=True,
            action_id=None,
            category=category,
            reason="Action does not require approval",
            auto_approved=True
        )

    def check_content(self, content: str) -> AuthorizationResult:
        """
        Check if content describes an action requiring authorization.

        Args:
            content: Content to analyze

        Returns:
            AuthorizationResult
        """
        for pattern, action, category in self._patterns:
            if pattern.search(content):
                return self.check_action(action, content[:200])

        return AuthorizationResult(
            requires_approval=False,
            is_approved=True,
            action_id=None,
            category=None,
            reason="No sensitive action detected",
            auto_approved=True
        )

    def _detect_action_type(self, description: str) -> tuple:
        """Detect action type from description."""
        for pattern, action, category in self._patterns:
            if pattern.search(description):
                risk = "medium"  # Default
                if action in self.SENSITIVE_ACTIONS:
                    _, risk = self.SENSITIVE_ACTIONS[action]
                return category, risk

        return None, None

    def approve(self, action_id: str, approved_by: str = "user") -> bool:
        """
        Approve a pending action.

        Args:
            action_id: ID of action to approve
            approved_by: Who approved it

        Returns:
            True if approved successfully
        """
        if action_id not in self._pending:
            logger.warning(f"Unknown action ID: {action_id}")
            return False

        request = self._pending[action_id]
        request.approved = True
        request.approved_by = approved_by
        request.approved_at = datetime.utcnow().isoformat()

        self._history.append(request)
        del self._pending[action_id]
        self._save_data()

        logger.info(f"Action approved: {request.action} by {approved_by}")
        return True

    def deny(self, action_id: str, denied_by: str = "user") -> bool:
        """
        Deny a pending action.

        Args:
            action_id: ID of action to deny
            denied_by: Who denied it

        Returns:
            True if denied successfully
        """
        if action_id not in self._pending:
            logger.warning(f"Unknown action ID: {action_id}")
            return False

        request = self._pending[action_id]
        request.approved = False
        request.approved_by = denied_by
        request.approved_at = datetime.utcnow().isoformat()

        self._history.append(request)
        del self._pending[action_id]
        self._save_data()

        logger.info(f"Action denied: {request.action} by {denied_by}")
        return True

    def is_approved(self, action_id: str) -> bool:
        """Check if an action has been approved."""
        if action_id in self._pending:
            return self._pending[action_id].approved or False

        # Check history
        for request in self._history:
            if request.action_id == action_id:
                return request.approved or False

        return False

    def get_pending(self) -> List[AuthorizationRequest]:
        """Get all pending authorization requests."""
        return list(self._pending.values())

    def cancel_pending(self, action_id: str) -> bool:
        """Cancel a pending request without approval or denial."""
        if action_id in self._pending:
            del self._pending[action_id]
            self._save_data()
            return True
        return False

    def get_stats(self) -> Dict:
        """Get authorization statistics."""
        return {
            "pending_requests": len(self._pending),
            "total_approved": sum(1 for r in self._history if r.approved),
            "total_denied": sum(1 for r in self._history if r.approved is False),
            "categories_protected": [c.value for c in self.require_approval_for],
            "auto_approve_low_risk": self.auto_approve_low_risk,
        }


# Global instance
_action_auth: Optional[ActionAuthorization] = None


def get_action_authorization() -> ActionAuthorization:
    """Get or create the global action authorization."""
    global _action_auth
    if _action_auth is None:
        _action_auth = ActionAuthorization()
    return _action_auth


def check_action_authorization(action: str, description: str = "") -> AuthorizationResult:
    """Check if an action requires authorization."""
    return get_action_authorization().check_action(action, description)


def requires_approval(action: str) -> bool:
    """Quick check if action requires approval."""
    result = get_action_authorization().check_action(action)
    return result.requires_approval


def approve_action(action_id: str, approved_by: str = "user") -> bool:
    """Approve an action."""
    return get_action_authorization().approve(action_id, approved_by)


def deny_action(action_id: str) -> bool:
    """Deny an action."""
    return get_action_authorization().deny(action_id)
