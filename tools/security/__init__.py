"""
Moltbook Security Module - Enhanced Security Layers for AI Agents.

This module provides comprehensive security for Moltbook agents:

Phase 1 (Critical):
- OutputScanner: Scan LLM outputs before posting
- ErrorSanitizer: Redact sensitive data from errors
- LogRedactor: Automatic log sanitization
- (Webhook sanitization in notifications module)

Phase 2 (Enhanced):
- ContextIsolator: Prevent indirect injection attacks
- SecretsManager: Encrypted credential storage
- PersistentRateLimiter: Rate limits that survive restarts
- AuditTrail: Security event logging with integrity

Phase 3 (AI Firewall):
- AIFirewallManager: AI-powered content moderation
- LlamaGuardFirewall: Meta's Llama Guard 3
- LLMGuardFirewall: ProtectAI's LLM Guard
- PatternFirewall: Regex-based fallback

Phase 4 (Moltbook-Specific):
- MemorySanitizer: Prevent persistent memory attacks
- EgressFirewall: Control external communication
- SkillVerifier: Validate plugins before execution
- CredentialMonitor: Detect credential theft attempts

Phase 5 (Social Media Defenses):
- SocialEngineeringDefense: Detect manipulation from other agents
- ReputationProtection: Prevent posting content that damages reputation
- InteractionAnalyzer: Detect coordinated attacks and sock puppets
- ContentProvenance: Track content origin and quote chains
- BehavioralFingerprintProtection: Prevent pattern-based targeting
- LinkSafety: Validate URLs before clicking/sharing
- SubmoltSafety: Assess risk level of submolts

Phase 6 (Data Protection & Authorization):
- ExfiltrationPrevention: Stop key theft and data leakage (encoding tricks, char extraction)
- FinancialSafety: Block unauthorized purchases and financial actions
- ActionAuthorization: Require explicit approval for sensitive actions

Configuration:
- SecurityConfig: Unified configuration management

ALL FEATURES ARE FREE:
- No external paid services required
- Uses local processing (regex, encryption, static analysis)
- AI firewall uses user's existing LLM or free local models

Usage:
    from tools.security import (
        OutputScanner, scan_output,
        ErrorSanitizer, sanitize_error,
        SecureLogger, configure_secure_logging,
        ContextIsolator, isolate_content,
        SecretsManager, get_secret,
        PersistentRateLimiter, check_rate_limit,
        AuditTrail, audit_log,
        AIFirewallManager, check_content,
        MemorySanitizer, sanitize_for_memory,
        EgressFirewall, check_egress,
        SkillVerifier, verify_skill,
        CredentialMonitor, check_for_credentials,
        SecurityConfig, get_security_config,
    )

Security Levels:
    - basic: Essential sanitization only
    - enhanced: Recommended for most users (default)
    - paranoid: Maximum security

Example:
    # Quick setup with enhanced security
    from tools.security import SecurityConfig, get_security_config

    config = SecurityConfig(level="enhanced")

    # Check output before posting
    from tools.security import scan_output
    result = scan_output(agent_response)
    if not result["is_safe"]:
        print(f"Blocked: {result['violations']}")

    # Sanitize errors before logging
    from tools.security import sanitize_error
    safe_error = sanitize_error(exception)
"""

# Phase 1: Critical Security
from .output_scanner import (
    OutputScanner,
    OutputScanResult,
    scan_output,
    redact_output,
    is_safe_to_post,
)

from .error_sanitizer import (
    ErrorSanitizer,
    SanitizationResult,
    get_sanitizer,
    sanitize_error,
    sanitize_message,
    safe_str,
)

from .log_redactor import (
    RedactingFormatter,
    SecureLogger,
    configure_secure_logging,
    get_secure_logger,
)

# Phase 2: Enhanced Security
from .context_isolator import (
    ContextIsolator,
    IsolatedContent,
    isolate_content,
    escape_user_content,
    build_safe_prompt,
)

from .secrets_manager import (
    SecretsManager,
    SecretsProvider,
    LocalEncryptedProvider,
    EnvironmentProvider,
    VaultProvider,
    AWSSecretsProvider,
    SecretValue,
    get_secrets_manager,
    get_secret,
    set_secret,
)

from .rate_limiter import (
    PersistentRateLimiter,
    RateLimitResult,
    RateLimitConfig,
    get_rate_limiter,
    check_rate_limit,
    record_action,
)

from .audit_trail import (
    AuditTrail,
    AuditEntry,
    get_audit_trail,
    audit_log,
    verify_audit_integrity,
)

# Phase 3: AI Firewall
from .ai_firewall import (
    AIFirewall,
    AIFirewallManager,
    FirewallResult,
    ContentDirection,
    UserLLMFirewall,
    LLMGuardFirewall,
    LlamaGuardFirewall,
    PatternFirewall,
    get_firewall_manager,
    check_content,
)

# Phase 4: Moltbook-Specific
from .memory_sanitizer import (
    MemorySanitizer,
    MemoryScanResult,
    MemoryEntry,
    get_memory_sanitizer,
    sanitize_for_memory,
    scan_memory,
)

from .egress_firewall import (
    EgressFirewall,
    EgressResult,
    EgressLog,
    get_egress_firewall,
    check_egress,
    is_url_allowed,
)

from .skill_verifier import (
    SkillVerifier,
    VerificationResult,
    Vulnerability,
    get_skill_verifier,
    verify_skill,
    is_skill_safe,
)

from .credential_monitor import (
    CredentialMonitor,
    MonitorResult,
    CredentialAlert,
    get_credential_monitor,
    check_for_credentials,
    detect_exfiltration,
)

# Configuration
from .config import (
    SecurityConfig,
    AIFirewallConfig,
    SecretsConfig,
    EgressConfig,
    SkillConfig,
    get_security_config,
    set_security_config,
    load_security_config,
)

# Phase 5: Social Media Defenses
from .social_engineering import (
    SocialEngineeringDefense,
    AgentTrustScore,
    ManipulationResult,
    get_social_defense,
    analyze_for_manipulation,
)

from .reputation_protection import (
    ReputationProtection,
    ReputationCheckResult,
    get_reputation_protector,
    check_reputation_risk,
)

from .interaction_analyzer import (
    InteractionAnalyzer,
    InteractionPattern,
    AnalysisResult,
    get_interaction_analyzer,
    record_interaction,
    analyze_interactions,
)

from .content_provenance import (
    ContentProvenance,
    ContentOrigin,
    ProvenanceCheckResult,
    get_content_provenance,
    check_provenance,
)

from .behavioral_fingerprint import (
    BehavioralFingerprintProtection,
    FingerprintConfig,
    get_fingerprint_protection,
    should_respond,
    get_style_modifier,
)

from .link_safety import (
    LinkSafety,
    LinkCheckResult,
    get_link_safety,
    check_url,
    check_text_for_urls,
)

from .submolt_safety import (
    SubmoltSafety,
    SubmoltProfile,
    SubmoltCheckResult,
    get_submolt_safety,
    check_submolt,
    is_submolt_safe,
)

# Phase 6: Data Protection & Authorization
from .exfiltration_prevention import (
    ExfiltrationPrevention,
    ExfiltrationCheckResult,
    get_exfiltration_prevention,
    check_for_exfiltration,
    sanitize_response,
)

from .financial_safety import (
    FinancialSafety,
    FinancialCheckResult,
    SpendingRecord,
    get_financial_safety,
    check_financial_request,
    is_financial_safe,
    block_all_financial_actions,
)

from .action_authorization import (
    ActionAuthorization,
    ActionCategory,
    AuthorizationRequest,
    AuthorizationResult,
    get_action_authorization,
    check_action_authorization,
    requires_approval,
    approve_action,
    deny_action,
)


__all__ = [
    # Phase 1
    "OutputScanner",
    "OutputScanResult",
    "scan_output",
    "redact_output",
    "is_safe_to_post",
    "ErrorSanitizer",
    "SanitizationResult",
    "get_sanitizer",
    "sanitize_error",
    "sanitize_message",
    "safe_str",
    "RedactingFormatter",
    "SecureLogger",
    "configure_secure_logging",
    "get_secure_logger",
    # Phase 2
    "ContextIsolator",
    "IsolatedContent",
    "isolate_content",
    "escape_user_content",
    "build_safe_prompt",
    "SecretsManager",
    "SecretsProvider",
    "LocalEncryptedProvider",
    "EnvironmentProvider",
    "VaultProvider",
    "AWSSecretsProvider",
    "SecretValue",
    "get_secrets_manager",
    "get_secret",
    "set_secret",
    "PersistentRateLimiter",
    "RateLimitResult",
    "RateLimitConfig",
    "get_rate_limiter",
    "check_rate_limit",
    "record_action",
    "AuditTrail",
    "AuditEntry",
    "get_audit_trail",
    "audit_log",
    "verify_audit_integrity",
    # Phase 3
    "AIFirewall",
    "AIFirewallManager",
    "FirewallResult",
    "ContentDirection",
    "UserLLMFirewall",
    "LLMGuardFirewall",
    "LlamaGuardFirewall",
    "PatternFirewall",
    "get_firewall_manager",
    "check_content",
    # Phase 4
    "MemorySanitizer",
    "MemoryScanResult",
    "MemoryEntry",
    "get_memory_sanitizer",
    "sanitize_for_memory",
    "scan_memory",
    "EgressFirewall",
    "EgressResult",
    "EgressLog",
    "get_egress_firewall",
    "check_egress",
    "is_url_allowed",
    "SkillVerifier",
    "VerificationResult",
    "Vulnerability",
    "get_skill_verifier",
    "verify_skill",
    "is_skill_safe",
    "CredentialMonitor",
    "MonitorResult",
    "CredentialAlert",
    "get_credential_monitor",
    "check_for_credentials",
    "detect_exfiltration",
    # Config
    "SecurityConfig",
    "AIFirewallConfig",
    "SecretsConfig",
    "EgressConfig",
    "SkillConfig",
    "get_security_config",
    "set_security_config",
    "load_security_config",
    # Phase 5: Social Media Defenses
    "SocialEngineeringDefense",
    "AgentTrustScore",
    "ManipulationResult",
    "get_social_defense",
    "analyze_for_manipulation",
    "ReputationProtection",
    "ReputationCheckResult",
    "get_reputation_protector",
    "check_reputation_risk",
    "InteractionAnalyzer",
    "InteractionPattern",
    "AnalysisResult",
    "get_interaction_analyzer",
    "record_interaction",
    "analyze_interactions",
    "ContentProvenance",
    "ContentOrigin",
    "ProvenanceCheckResult",
    "get_content_provenance",
    "check_provenance",
    "BehavioralFingerprintProtection",
    "FingerprintConfig",
    "get_fingerprint_protection",
    "should_respond",
    "get_style_modifier",
    "LinkSafety",
    "LinkCheckResult",
    "get_link_safety",
    "check_url",
    "check_text_for_urls",
    "SubmoltSafety",
    "SubmoltProfile",
    "SubmoltCheckResult",
    "get_submolt_safety",
    "check_submolt",
    "is_submolt_safe",
    # Phase 6: Data Protection & Authorization
    "ExfiltrationPrevention",
    "ExfiltrationCheckResult",
    "get_exfiltration_prevention",
    "check_for_exfiltration",
    "sanitize_response",
    "FinancialSafety",
    "FinancialCheckResult",
    "SpendingRecord",
    "get_financial_safety",
    "check_financial_request",
    "is_financial_safe",
    "block_all_financial_actions",
    "ActionAuthorization",
    "ActionCategory",
    "AuthorizationRequest",
    "AuthorizationResult",
    "get_action_authorization",
    "check_action_authorization",
    "requires_approval",
    "approve_action",
    "deny_action",
]

__version__ = "1.0.0"
