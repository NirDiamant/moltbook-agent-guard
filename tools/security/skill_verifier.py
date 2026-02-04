"""
Skill Verifier - Validate Plugins Before Execution.

22-26% of Moltbook skills contain vulnerabilities. This module
verifies skill integrity and scans for dangerous patterns before
allowing execution.

Features:
- Manifest verification (SKILL.md requirements)
- Static analysis for vulnerability patterns
- Permission checking
- Signature verification (optional)

Based on security research showing common skill vulnerabilities:
- Arbitrary code execution (eval, exec)
- Shell injection (subprocess, os.system)
- Credential access patterns
- Hardcoded webhook URLs
"""

import os
import re
import ast
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """A detected vulnerability."""
    severity: str  # "low", "medium", "high", "critical"
    category: str
    description: str
    file_path: str
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of skill verification."""
    is_verified: bool
    skill_name: str
    skill_path: str
    manifest_valid: bool
    manifest_errors: List[str] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    permissions_declared: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)


class SkillVerifier:
    """
    Verify skill integrity and permissions before execution.

    Usage:
        verifier = SkillVerifier()

        # Before running a skill
        result = verifier.verify(skill_path)
        if not result.is_verified:
            print(f"Skill blocked: {result.vulnerabilities}")
    """

    # Required manifest fields
    REQUIRED_MANIFEST_FIELDS = [
        "name",
        "version",
        "description",
    ]

    # Optional but recommended for security
    RECOMMENDED_MANIFEST_FIELDS = [
        "permissions",
        "author",
        "repository",
    ]

    # Dangerous function patterns (static analysis)
    DANGEROUS_PATTERNS = {
        "code_execution": {
            "severity": "critical",
            "patterns": [
                r"\beval\s*\(",
                r"\bexec\s*\(",
                r"\bcompile\s*\(",
                r"__import__\s*\(",
            ],
            "description": "Arbitrary code execution"
        },
        "shell_command": {
            "severity": "critical",
            "patterns": [
                r"\bos\.system\s*\(",
                r"\bos\.popen\s*\(",
                r"\bsubprocess\.(?:run|call|Popen|check_output)\s*\(",
                r"\bcommands\.getoutput\s*\(",
            ],
            "description": "Shell command execution"
        },
        "file_operations": {
            "severity": "high",
            "patterns": [
                r"\bopen\s*\([^)]*['\"]w['\"]",  # Write mode
                r"\bos\.remove\s*\(",
                r"\bos\.unlink\s*\(",
                r"\bshutil\.rmtree\s*\(",
                r"\bos\.rmdir\s*\(",
            ],
            "description": "Dangerous file operations"
        },
        "network_access": {
            "severity": "high",
            "patterns": [
                r"\brequests\.(get|post|put|delete|patch)\s*\(",
                r"\burllib\.request\.urlopen\s*\(",
                r"\bhttpx\.(get|post|put|delete)\s*\(",
                r"socket\.socket\s*\(",
            ],
            "description": "Network access"
        },
        "credential_access": {
            "severity": "critical",
            "patterns": [
                r"os\.environ\.get\s*\(\s*['\"].*(?:KEY|SECRET|TOKEN|PASSWORD)",
                r"os\.environ\s*\[\s*['\"].*(?:KEY|SECRET|TOKEN|PASSWORD)",
                r"getenv\s*\(\s*['\"].*(?:KEY|SECRET|TOKEN|PASSWORD)",
            ],
            "description": "Credential access"
        },
        "hardcoded_urls": {
            "severity": "medium",
            "patterns": [
                r"https?://(?:webhook|hooks|ngrok|pipedream)",
                r"https?://[^/]+\.(?:ngrok|pipedream|requestbin)\.",
            ],
            "description": "Hardcoded external URLs"
        },
        "pickle_deserialization": {
            "severity": "critical",
            "patterns": [
                r"\bpickle\.loads?\s*\(",
                r"\bcPickle\.loads?\s*\(",
                r"\byaml\.load\s*\([^)]*Loader\s*=\s*yaml\.(?:Unsafe)?Loader",
            ],
            "description": "Unsafe deserialization"
        },
    }

    # Blocked imports
    BLOCKED_IMPORTS = {
        "ctypes",
        "multiprocessing",
        "threading",  # Can be used to bypass restrictions
        "pickle",
        "cPickle",
        "marshal",
    }

    def __init__(self,
                 require_manifest: bool = True,
                 require_signature: bool = False,
                 blocked_functions: List[str] = None,
                 max_risk_score: float = 5.0):
        """
        Initialize the skill verifier.

        Args:
            require_manifest: Whether to require SKILL.md manifest
            require_signature: Whether to require cryptographic signature
            blocked_functions: Additional functions to block
            max_risk_score: Maximum allowed risk score
        """
        self.require_manifest = require_manifest
        self.require_signature = require_signature
        self.max_risk_score = max_risk_score

        # Compile patterns
        self._compile_patterns()

        # Add additional blocked functions
        if blocked_functions:
            for func in blocked_functions:
                self.DANGEROUS_PATTERNS[f"custom_{func}"] = {
                    "severity": "high",
                    "patterns": [rf"\b{re.escape(func)}\s*\("],
                    "description": f"Blocked function: {func}"
                }
            self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns."""
        self._compiled_patterns = {}
        for category, data in self.DANGEROUS_PATTERNS.items():
            self._compiled_patterns[category] = {
                "severity": data["severity"],
                "description": data["description"],
                "patterns": [re.compile(p) for p in data["patterns"]]
            }

    def verify_manifest(self, skill_path: str) -> Tuple[bool, List[str], Dict]:
        """
        Check SKILL.md manifest for required declarations.

        Args:
            skill_path: Path to skill directory

        Returns:
            (is_valid, errors, manifest_data)
        """
        skill_dir = Path(skill_path)
        manifest_path = skill_dir / "SKILL.md"

        if not manifest_path.exists():
            if self.require_manifest:
                return False, ["SKILL.md manifest not found"], {}
            return True, [], {}

        errors = []
        manifest_data = {}

        try:
            content = manifest_path.read_text()

            # Parse markdown frontmatter or simple key: value
            lines = content.split('\n')
            in_frontmatter = False

            for line in lines:
                line = line.strip()

                if line == '---':
                    in_frontmatter = not in_frontmatter
                    continue

                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    manifest_data[key] = value

            # Check required fields
            for field in self.REQUIRED_MANIFEST_FIELDS:
                if field not in manifest_data:
                    errors.append(f"Missing required field: {field}")

            # Check recommended fields (warning only)
            for field in self.RECOMMENDED_MANIFEST_FIELDS:
                if field not in manifest_data:
                    logger.info(f"Skill missing recommended field: {field}")

        except Exception as e:
            errors.append(f"Failed to parse manifest: {e}")

        return len(errors) == 0, errors, manifest_data

    def scan_for_vulnerabilities(self, skill_path: str) -> List[Vulnerability]:
        """
        Static analysis for common vulnerability patterns.

        Args:
            skill_path: Path to skill directory

        Returns:
            List of detected vulnerabilities
        """
        vulnerabilities = []
        skill_dir = Path(skill_path)

        # Scan all Python files
        for py_file in skill_dir.rglob("*.py"):
            try:
                content = py_file.read_text()
                rel_path = str(py_file.relative_to(skill_dir))

                # Pattern-based scanning
                for category, data in self._compiled_patterns.items():
                    for pattern in data["patterns"]:
                        for i, line in enumerate(content.split('\n'), 1):
                            if pattern.search(line):
                                vulnerabilities.append(Vulnerability(
                                    severity=data["severity"],
                                    category=category,
                                    description=data["description"],
                                    file_path=rel_path,
                                    line_number=i,
                                    code_snippet=line.strip()[:100]
                                ))

                # AST-based scanning for imports
                try:
                    tree = ast.parse(content)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            for alias in node.names:
                                if alias.name in self.BLOCKED_IMPORTS:
                                    vulnerabilities.append(Vulnerability(
                                        severity="high",
                                        category="blocked_import",
                                        description=f"Blocked import: {alias.name}",
                                        file_path=rel_path,
                                        line_number=node.lineno
                                    ))
                        elif isinstance(node, ast.ImportFrom):
                            if node.module and node.module.split('.')[0] in self.BLOCKED_IMPORTS:
                                vulnerabilities.append(Vulnerability(
                                    severity="high",
                                    category="blocked_import",
                                    description=f"Blocked import from: {node.module}",
                                    file_path=rel_path,
                                    line_number=node.lineno
                                ))
                except SyntaxError:
                    vulnerabilities.append(Vulnerability(
                        severity="low",
                        category="syntax_error",
                        description="Python syntax error in file",
                        file_path=rel_path
                    ))

            except Exception as e:
                logger.warning(f"Error scanning {py_file}: {e}")

        return vulnerabilities

    def verify_signature(self, skill_path: str) -> Tuple[bool, str]:
        """
        Verify skill signature if present.

        Args:
            skill_path: Path to skill directory

        Returns:
            (is_valid, message)
        """
        skill_dir = Path(skill_path)
        sig_path = skill_dir / "SKILL.sig"

        if not sig_path.exists():
            if self.require_signature:
                return False, "Signature required but not found"
            return True, "No signature (not required)"

        # TODO: Implement actual signature verification
        # For now, just check that signature file exists
        return True, "Signature present (verification not implemented)"

    def verify(self, skill_path: str) -> VerificationResult:
        """
        Perform full verification of a skill.

        Args:
            skill_path: Path to skill directory

        Returns:
            VerificationResult with all findings
        """
        skill_dir = Path(skill_path)
        skill_name = skill_dir.name

        # Verify manifest
        manifest_valid, manifest_errors, manifest_data = self.verify_manifest(skill_path)

        # Scan for vulnerabilities
        vulnerabilities = self.scan_for_vulnerabilities(skill_path)

        # Calculate risk score
        severity_scores = {"low": 0.5, "medium": 1.0, "high": 2.0, "critical": 5.0}
        risk_score = sum(severity_scores.get(v.severity, 1.0) for v in vulnerabilities)

        # Check signature
        sig_valid, sig_message = self.verify_signature(skill_path)

        # Get declared permissions
        permissions = []
        if "permissions" in manifest_data:
            permissions = [p.strip() for p in manifest_data["permissions"].split(",")]

        # Generate recommendations
        recommendations = []
        if not manifest_valid:
            recommendations.append("Add a valid SKILL.md manifest")
        if vulnerabilities:
            critical_count = sum(1 for v in vulnerabilities if v.severity == "critical")
            if critical_count > 0:
                recommendations.append(f"Fix {critical_count} critical vulnerabilities before use")
        if risk_score > self.max_risk_score:
            recommendations.append("Risk score too high - review and fix issues")

        # Determine if verified
        is_verified = (
            (manifest_valid or not self.require_manifest) and
            (sig_valid or not self.require_signature) and
            risk_score <= self.max_risk_score and
            not any(v.severity == "critical" for v in vulnerabilities)
        )

        return VerificationResult(
            is_verified=is_verified,
            skill_name=skill_name,
            skill_path=str(skill_path),
            manifest_valid=manifest_valid,
            manifest_errors=manifest_errors,
            vulnerabilities=vulnerabilities,
            permissions_declared=permissions,
            risk_score=risk_score,
            recommendations=recommendations
        )

    def quick_scan(self, skill_path: str) -> Tuple[bool, List[str]]:
        """
        Quick scan for critical issues only.

        Args:
            skill_path: Path to skill

        Returns:
            (is_safe, issues)
        """
        issues = []
        vulnerabilities = self.scan_for_vulnerabilities(skill_path)

        critical = [v for v in vulnerabilities if v.severity == "critical"]
        for v in critical:
            issues.append(f"{v.category}: {v.description} ({v.file_path}:{v.line_number})")

        return len(critical) == 0, issues


# Global instance
_skill_verifier: Optional[SkillVerifier] = None


def get_skill_verifier() -> SkillVerifier:
    """Get or create the global skill verifier."""
    global _skill_verifier
    if _skill_verifier is None:
        _skill_verifier = SkillVerifier()
    return _skill_verifier


def verify_skill(skill_path: str) -> VerificationResult:
    """
    Verify a skill before execution.

    Args:
        skill_path: Path to skill directory

    Returns:
        VerificationResult
    """
    return get_skill_verifier().verify(skill_path)


def is_skill_safe(skill_path: str) -> bool:
    """
    Quick check if skill is safe to run.

    Args:
        skill_path: Path to skill

    Returns:
        True if safe
    """
    is_safe, _ = get_skill_verifier().quick_scan(skill_path)
    return is_safe
