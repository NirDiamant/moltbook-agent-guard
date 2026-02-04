"""
Security Configuration - Parse and validate security settings.

Provides configuration management for all security features with
support for three security levels: basic, enhanced, and paranoid.

Security Level Defaults:
| Feature              | Basic | Enhanced | Paranoid |
|----------------------|-------|----------|----------|
| Output Scanning      | ON    | ON       | ON       |
| Error Sanitization   | ON    | ON       | ON       |
| Log Redaction        | ON    | ON       | ON       |
| Webhook Sanitization | ON    | ON       | ON       |
| Context Isolation    | OFF   | ON       | ON       |
| Secrets Encryption   | OFF   | ON       | ON       |
| Persistent Rate Limit| OFF   | ON       | ON       |
| Audit Trail          | OFF   | ON       | ON       |
| AI Firewall          | OFF   | ON       | ON       |
| Memory Sanitizer     | OFF   | ON       | ON       |
| Egress Firewall      | OFF   | ON       | ON       |
| Skill Verifier       | OFF   | OFF      | ON       |
| Credential Monitor   | OFF   | ON       | ON       |
"""

import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
import yaml
import logging

logger = logging.getLogger(__name__)


@dataclass
class AIFirewallConfig:
    """AI Firewall configuration."""
    enabled: bool = True
    provider: str = "pattern"  # "user_llm", "llm_guard", "llama_guard", "pattern"
    scan_inputs: bool = True
    scan_outputs: bool = True
    block_unsafe: bool = True
    llama_guard_provider: str = "local"  # "local", "groq"
    groq_api_key: Optional[str] = None


@dataclass
class SecretsConfig:
    """Secrets manager configuration."""
    provider: str = "local_encrypted"  # "env", "local_encrypted", "vault", "aws"
    vault_url: Optional[str] = None
    vault_token: Optional[str] = None
    aws_region: Optional[str] = None


@dataclass
class RateLimitConfig:
    """Rate limiter configuration."""
    posts_per_day: int = 5
    comments_per_day: int = 50
    post_cooldown_seconds: int = 1800
    comment_cooldown_seconds: int = 20
    state_file: str = ".moltbook/rate_state.json"


@dataclass
class EgressConfig:
    """Egress firewall configuration."""
    enabled: bool = True
    mode: str = "allowlist"  # "allowlist" or "blocklist"
    allowed_domains: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)
    max_requests_per_hour: int = 1000


@dataclass
class SkillConfig:
    """Skill verifier configuration."""
    require_manifest: bool = True
    require_signature: bool = False
    auto_scan: bool = True
    blocked_functions: List[str] = field(default_factory=lambda: ["eval", "exec", "os.system"])
    max_risk_score: float = 5.0


@dataclass
class SecurityConfig:
    """
    Complete security configuration.

    Usage:
        config = SecurityConfig.from_yaml("agent_config.yaml")
        # or
        config = SecurityConfig.from_dict({"level": "enhanced"})
        # or
        config = SecurityConfig(level="paranoid")
    """
    # Security level
    level: str = "enhanced"  # "basic", "enhanced", "paranoid"

    # Individual feature toggles
    output_scanning: bool = True
    error_sanitization: bool = True
    log_redaction: bool = True
    webhook_sanitization: bool = True
    context_isolation: bool = False
    secrets_encryption: bool = False
    persistent_rate_limits: bool = False
    audit_trail: bool = False
    memory_sanitizer: bool = False
    egress_firewall: bool = False
    skill_verifier: bool = False
    credential_monitor: bool = False

    # Sub-configurations
    ai_firewall: AIFirewallConfig = field(default_factory=AIFirewallConfig)
    secrets: SecretsConfig = field(default_factory=SecretsConfig)
    rate_limits: RateLimitConfig = field(default_factory=RateLimitConfig)
    egress: EgressConfig = field(default_factory=EgressConfig)
    skills: SkillConfig = field(default_factory=SkillConfig)

    def __post_init__(self):
        """Apply security level defaults after initialization."""
        self._apply_level_defaults()

    def _apply_level_defaults(self):
        """Apply defaults based on security level."""
        if self.level == "basic":
            # Basic: Only essential sanitization
            self.output_scanning = True
            self.error_sanitization = True
            self.log_redaction = True
            self.webhook_sanitization = True
            self.context_isolation = False
            self.secrets_encryption = False
            self.persistent_rate_limits = False
            self.audit_trail = False
            self.ai_firewall.enabled = False
            self.memory_sanitizer = False
            self.egress_firewall = False
            self.skill_verifier = False
            self.credential_monitor = False

        elif self.level == "enhanced":
            # Enhanced: Recommended for most users
            self.output_scanning = True
            self.error_sanitization = True
            self.log_redaction = True
            self.webhook_sanitization = True
            self.context_isolation = True
            self.secrets_encryption = True
            self.persistent_rate_limits = True
            self.audit_trail = True
            self.ai_firewall.enabled = True
            self.memory_sanitizer = True
            self.egress_firewall = True
            self.skill_verifier = False
            self.credential_monitor = True

        elif self.level == "paranoid":
            # Paranoid: Maximum security
            self.output_scanning = True
            self.error_sanitization = True
            self.log_redaction = True
            self.webhook_sanitization = True
            self.context_isolation = True
            self.secrets_encryption = True
            self.persistent_rate_limits = True
            self.audit_trail = True
            self.ai_firewall.enabled = True
            self.memory_sanitizer = True
            self.egress_firewall = True
            self.skill_verifier = True
            self.credential_monitor = True
            # Paranoid extras
            self.skills.require_manifest = True
            self.egress.mode = "allowlist"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityConfig":
        """
        Create config from dictionary.

        Args:
            data: Configuration dictionary

        Returns:
            SecurityConfig instance
        """
        # Extract sub-configs
        ai_firewall_data = data.pop("ai_firewall", {})
        secrets_data = data.pop("secrets", {})
        rate_limits_data = data.pop("rate_limits", {})
        egress_data = data.pop("egress", {})
        skills_data = data.pop("skills", {})

        # Create main config (will apply level defaults)
        config = cls(**{k: v for k, v in data.items() if hasattr(cls, k)})

        # Override with explicit sub-configs
        if ai_firewall_data:
            for key, value in ai_firewall_data.items():
                if hasattr(config.ai_firewall, key):
                    setattr(config.ai_firewall, key, value)

        if secrets_data:
            for key, value in secrets_data.items():
                if hasattr(config.secrets, key):
                    setattr(config.secrets, key, value)

        if rate_limits_data:
            for key, value in rate_limits_data.items():
                if hasattr(config.rate_limits, key):
                    setattr(config.rate_limits, key, value)

        if egress_data:
            for key, value in egress_data.items():
                if hasattr(config.egress, key):
                    setattr(config.egress, key, value)

        if skills_data:
            for key, value in skills_data.items():
                if hasattr(config.skills, key):
                    setattr(config.skills, key, value)

        return config

    @classmethod
    def from_yaml(cls, yaml_path: str) -> "SecurityConfig":
        """
        Load config from YAML file.

        Args:
            yaml_path: Path to YAML config file

        Returns:
            SecurityConfig instance
        """
        path = Path(yaml_path)

        if not path.exists():
            logger.warning(f"Config file not found: {yaml_path}, using defaults")
            return cls()

        try:
            with open(path) as f:
                data = yaml.safe_load(f)

            # Extract security section
            security_data = data.get("security", {})
            return cls.from_dict(security_data)

        except Exception as e:
            logger.error(f"Failed to load security config: {e}")
            return cls()

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "level": self.level,
            "output_scanning": self.output_scanning,
            "error_sanitization": self.error_sanitization,
            "log_redaction": self.log_redaction,
            "webhook_sanitization": self.webhook_sanitization,
            "context_isolation": self.context_isolation,
            "secrets_encryption": self.secrets_encryption,
            "persistent_rate_limits": self.persistent_rate_limits,
            "audit_trail": self.audit_trail,
            "memory_sanitizer": self.memory_sanitizer,
            "egress_firewall": self.egress_firewall,
            "skill_verifier": self.skill_verifier,
            "credential_monitor": self.credential_monitor,
            "ai_firewall": {
                "enabled": self.ai_firewall.enabled,
                "provider": self.ai_firewall.provider,
                "scan_inputs": self.ai_firewall.scan_inputs,
                "scan_outputs": self.ai_firewall.scan_outputs,
                "block_unsafe": self.ai_firewall.block_unsafe,
            },
            "secrets": {
                "provider": self.secrets.provider,
            },
            "rate_limits": {
                "posts_per_day": self.rate_limits.posts_per_day,
                "comments_per_day": self.rate_limits.comments_per_day,
            },
            "egress": {
                "enabled": self.egress.enabled,
                "mode": self.egress.mode,
            },
            "skills": {
                "require_manifest": self.skills.require_manifest,
                "auto_scan": self.skills.auto_scan,
            }
        }

    def get_enabled_features(self) -> List[str]:
        """Get list of enabled security features."""
        features = []

        if self.output_scanning:
            features.append("output_scanning")
        if self.error_sanitization:
            features.append("error_sanitization")
        if self.log_redaction:
            features.append("log_redaction")
        if self.webhook_sanitization:
            features.append("webhook_sanitization")
        if self.context_isolation:
            features.append("context_isolation")
        if self.secrets_encryption:
            features.append("secrets_encryption")
        if self.persistent_rate_limits:
            features.append("persistent_rate_limits")
        if self.audit_trail:
            features.append("audit_trail")
        if self.ai_firewall.enabled:
            features.append(f"ai_firewall ({self.ai_firewall.provider})")
        if self.memory_sanitizer:
            features.append("memory_sanitizer")
        if self.egress_firewall:
            features.append("egress_firewall")
        if self.skill_verifier:
            features.append("skill_verifier")
        if self.credential_monitor:
            features.append("credential_monitor")

        return features

    def validate(self) -> List[str]:
        """
        Validate configuration for potential issues.

        Returns:
            List of warning messages
        """
        warnings = []

        if self.level not in ["basic", "enhanced", "paranoid"]:
            warnings.append(f"Unknown security level: {self.level}")

        if not self.error_sanitization:
            warnings.append("Error sanitization disabled - credentials may leak in errors")

        if not self.log_redaction:
            warnings.append("Log redaction disabled - credentials may appear in logs")

        if self.ai_firewall.enabled and self.ai_firewall.provider == "user_llm":
            warnings.append("AI firewall using user_llm - requires LLM client")

        if self.ai_firewall.enabled and self.ai_firewall.provider == "llama_guard":
            if self.ai_firewall.llama_guard_provider == "groq":
                if not self.ai_firewall.groq_api_key:
                    warnings.append("Llama Guard groq provider requires GROQ_API_KEY")

        if self.egress_firewall and not self.egress.allowed_domains:
            warnings.append("Egress firewall enabled with no allowed domains - all external requests will be blocked")

        return warnings


# Global config instance
_security_config: Optional[SecurityConfig] = None


def get_security_config() -> SecurityConfig:
    """Get the global security configuration."""
    global _security_config
    if _security_config is None:
        # Try to load from default location
        _security_config = SecurityConfig.from_yaml("agent_config.yaml")
    return _security_config


def set_security_config(config: SecurityConfig):
    """Set the global security configuration."""
    global _security_config
    _security_config = config


def load_security_config(yaml_path: str) -> SecurityConfig:
    """
    Load and set security configuration from YAML.

    Args:
        yaml_path: Path to config file

    Returns:
        Loaded SecurityConfig
    """
    config = SecurityConfig.from_yaml(yaml_path)
    set_security_config(config)
    return config
