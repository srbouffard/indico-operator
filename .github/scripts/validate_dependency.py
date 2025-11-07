#!/usr/bin/env python3

# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Dependency validation helper script for GitHub Copilot Agent.

This script provides utility functions for validating dependency updates,
including version parsing, security scanning, and risk assessment.
"""

import argparse
import json
import re
import subprocess
import sys
from typing import Dict, List, Optional, Tuple


class VersionBump:
    """Represents a version bump classification."""

    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNKNOWN = "unknown"


class RiskLevel:
    """Represents risk levels for dependency updates."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Default severity when vulnerabilities are found but severity cannot be determined
DEFAULT_VULNERABILITY_SEVERITY = "medium"


def parse_version(version_string: str) -> Tuple[int, int, int]:
    """Parse a semantic version string into major, minor, patch components.

    Args:
        version_string: Version string like "1.10.24"

    Returns:
        Tuple of (major, minor, patch) integers

    Raises:
        ValueError: If version string is not in valid semver format
    """
    # Remove common prefixes
    version_string = version_string.lstrip("v")

    # Match semantic version pattern
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", version_string)
    if not match:
        raise ValueError(f"Invalid version format: {version_string}")

    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def classify_version_bump(old_version: str, new_version: str) -> str:
    """Classify the type of version bump.

    Args:
        old_version: Old version string
        new_version: New version string

    Returns:
        One of VersionBump constants (MAJOR, MINOR, PATCH, UNKNOWN)
    """
    try:
        old_major, old_minor, old_patch = parse_version(old_version)
        new_major, new_minor, new_patch = parse_version(new_version)

        if new_major > old_major:
            return VersionBump.MAJOR
        elif new_minor > old_minor:
            return VersionBump.MINOR
        elif new_patch > old_patch:
            return VersionBump.PATCH
        else:
            return VersionBump.UNKNOWN
    except ValueError:
        return VersionBump.UNKNOWN


def parse_pr_title(title: str) -> Optional[Dict[str, str]]:
    """Parse Renovate PR title to extract package and version info.

    Expected format: "Update [package] from X.Y.Z to A.B.C"

    Args:
        title: PR title string

    Returns:
        Dict with package, old_version, new_version, and bump_type, or None
    """
    # Common Renovate patterns
    patterns = [
        r"Update\s+([^\s]+)\s+from\s+([^\s]+)\s+to\s+([^\s]+)",
        r"Update\s+dependency\s+([^\s]+)\s+to\s+v?([^\s]+)",
        r"chore\(deps\):\s+update\s+([^\s]+)\s+from\s+([^\s]+)\s+to\s+([^\s]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, title, re.IGNORECASE)
        if match:
            groups = match.groups()
            if len(groups) == 3:
                package, old_version, new_version = groups
            elif len(groups) == 2:
                package, new_version = groups
                old_version = "unknown"
            else:
                continue

            bump_type = classify_version_bump(old_version, new_version)

            return {
                "package": package,
                "old_version": old_version,
                "new_version": new_version,
                "bump_type": bump_type,
            }

    return None


def get_initial_risk_level(bump_type: str) -> str:
    """Get initial risk level based on version bump type.

    Args:
        bump_type: One of VersionBump constants

    Returns:
        One of RiskLevel constants
    """
    if bump_type == VersionBump.PATCH:
        return RiskLevel.LOW
    elif bump_type == VersionBump.MINOR:
        return RiskLevel.MEDIUM
    elif bump_type == VersionBump.MAJOR:
        return RiskLevel.HIGH
    else:
        # Default to MEDIUM for unknown bump types as a balanced approach
        # Not too permissive (LOW) but allows for manual review (not HIGH/CRITICAL)
        return RiskLevel.MEDIUM


def run_pip_audit(requirements_file: str = "requirements.txt") -> Dict:
    """Run pip-audit on a requirements file.

    Args:
        requirements_file: Path to requirements.txt file

    Returns:
        Dict with scan results including vulnerabilities found
    """
    result = {
        "success": False,
        "vulnerabilities": [],
        "error": None,
    }

    try:
        # Check if pip-audit is installed
        subprocess.run(
            ["pip-audit", "--version"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Install pip-audit if not available
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "pip-audit"],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            result["error"] = f"Failed to install pip-audit: {e}"
            return result

    try:
        # Run pip-audit with JSON output
        proc = subprocess.run(
            ["pip-audit", "-r", requirements_file, "--format", "json"],
            capture_output=True,
            text=True,
            check=False,  # Don't raise on non-zero exit (vulnerabilities found)
        )

        if proc.returncode in [0, 1]:  # 0=no vulns, 1=vulns found
            audit_data = json.loads(proc.stdout)
            result["success"] = True
            # Extract vulnerabilities from pip-audit JSON output
            # pip-audit JSON format (as of v2.x) uses "dependencies" key for vulnerable packages
            # Each dependency contains package info and a "vulns" list with vulnerability details
            # Example: {"dependencies": [{"name": "pkg", "version": "1.0", "vulns": [...]}]}
            if isinstance(audit_data, dict):
                result["vulnerabilities"] = audit_data.get("dependencies", [])
            else:
                # Fallback for unexpected format
                result["vulnerabilities"] = []
        else:
            result["error"] = f"pip-audit failed: {proc.stderr}"

    except json.JSONDecodeError as e:
        result["error"] = f"Failed to parse pip-audit output: {e}"
    except Exception as e:
        result["error"] = f"Unexpected error running pip-audit: {e}"

    return result


def extract_vulnerability_severity(vulnerabilities: List[Dict]) -> Optional[str]:
    """Extract the highest severity level from vulnerability data.

    Args:
        vulnerabilities: List of vulnerability dicts from pip-audit

    Returns:
        Highest severity level found: critical, high, medium, low, or None
    """
    if not vulnerabilities:
        return None

    severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    max_severity = None
    max_level = 0

    for vuln in vulnerabilities:
        # pip-audit may include vulnerabilities within dependency dict
        vuln_list = vuln.get("vulns", [])
        for v in vuln_list:
            # Try to extract severity from various possible fields
            severity = None

            # Check for explicit severity field (preferred method)
            if "severity" in v:
                severity = v["severity"].lower()
            # If severity not explicitly provided, vulnerabilities with CVE aliases
            # or fix information still indicate a known issue worth flagging
            elif "fix_versions" in v or "aliases" in v:
                # These fields indicate a documented vulnerability
                # Use default severity as a conservative estimate
                severity = DEFAULT_VULNERABILITY_SEVERITY

            if severity and severity in severity_levels:
                level = severity_levels[severity]
                if level > max_level:
                    max_level = level
                    max_severity = severity

    # If we found vulnerabilities but couldn't determine severity, use default
    if not max_severity and vulnerabilities:
        max_severity = DEFAULT_VULNERABILITY_SEVERITY

    return max_severity


def calculate_final_risk(
    initial_risk: str,
    has_vulnerabilities: bool,
    vulnerability_severity: Optional[str] = None,
    ci_failed: bool = False,
) -> str:
    """Calculate final risk level based on all factors.

    Args:
        initial_risk: Initial risk based on version bump
        has_vulnerabilities: Whether vulnerabilities were found
        vulnerability_severity: Highest severity level (critical, high, medium, low)
        ci_failed: Whether CI checks failed

    Returns:
        Final risk level (one of RiskLevel constants)
    """
    # Start with initial risk
    risk_score = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }

    current_score = risk_score.get(initial_risk, 2)

    # Escalate based on vulnerabilities
    if has_vulnerabilities:
        if vulnerability_severity in ["critical", "high"]:
            current_score = max(current_score, 4)  # Critical
        elif vulnerability_severity == "medium":
            current_score = max(current_score, 3)  # High
        else:
            current_score = max(current_score, 2)  # Medium

    # Escalate if CI failed
    if ci_failed:
        current_score = max(current_score, 3)  # At least High

    # Convert score back to risk level with explicit mapping for consistency
    score_to_level = {
        1: RiskLevel.LOW,
        2: RiskLevel.MEDIUM,
        3: RiskLevel.HIGH,
        4: RiskLevel.CRITICAL,
    }

    return score_to_level.get(current_score, RiskLevel.MEDIUM)


def generate_assessment_report(
    package_info: Dict,
    security_results: Dict,
    ci_status: Optional[str] = None,
    final_risk: str = RiskLevel.MEDIUM,
) -> str:
    """Generate a formatted assessment report.

    Args:
        package_info: Dict with package, versions, and bump_type
        security_results: Results from security scanning
        ci_status: Status of CI checks
        final_risk: Final calculated risk level

    Returns:
        Formatted markdown report
    """
    risk_emoji = {
        RiskLevel.LOW: "🟢 Low",
        RiskLevel.MEDIUM: "🟡 Medium",
        RiskLevel.HIGH: "🟠 High",
        RiskLevel.CRITICAL: "🔴 Critical",
    }

    report = "## 🤖 Dependency Update Assessment\n\n"
    report += f"**Package**: {package_info.get('package', 'Unknown')}\n"
    report += f"**Version Change**: {package_info.get('old_version', '?')} → "
    report += f"{package_info.get('new_version', '?')}\n"
    report += f"**Bump Type**: {package_info.get('bump_type', 'unknown').title()}\n"
    report += f"**Risk Level**: {risk_emoji.get(final_risk, '🟡 Medium')}\n\n"

    # Security scan section
    report += "### Security Scan\n"
    if security_results.get("success"):
        vulns = security_results.get("vulnerabilities", [])
        if vulns:
            report += f"⚠️ {len(vulns)} vulnerabilities found:\n"
            for vuln in vulns[:5]:  # Limit to first 5
                name = vuln.get("name", "unknown")
                version = vuln.get("version", "unknown")
                report += f"- {name} {version}\n"
        else:
            report += "✅ No vulnerabilities found\n"
    else:
        error = security_results.get("error", "Unknown error")
        report += f"⚠️ Security scan failed: {error}\n"

    # CI status section
    report += "\n### CI Status\n"
    if ci_status == "success":
        report += "✅ All checks passed\n"
    elif ci_status == "failure":
        report += "❌ Some checks failed\n"
    elif ci_status == "pending":
        report += "⏳ Checks in progress\n"
    else:
        report += "⏳ Waiting for CI checks\n"

    # Recommendation section
    report += "\n### Recommendation\n"
    if final_risk == RiskLevel.LOW:
        report += "✅ Safe to merge after review\n"
    elif final_risk == RiskLevel.MEDIUM:
        report += "⚠️ Review required before merge\n"
    elif final_risk == RiskLevel.HIGH:
        report += "⚠️ Careful review required - consider testing in staging\n"
    else:  # CRITICAL
        report += "🚨 Do not merge - critical issues found\n"

    report += "\n### Rollback Plan\n"
    report += "If issues occur after merge:\n"
    report += "```bash\n"
    report += "git revert <commit-sha>\n"
    report += "```\n"

    return report


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Validate dependency updates for Renovate PRs"
    )
    parser.add_argument(
        "--pr-title",
        help="PR title to parse for version information",
    )
    parser.add_argument(
        "--requirements",
        default="requirements.txt",
        help="Path to requirements.txt file",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Run security scan with pip-audit",
    )
    parser.add_argument(
        "--ci-status",
        choices=["success", "failure", "pending", "none"],
        default="none",
        help="CI check status",
    )
    parser.add_argument(
        "--output",
        choices=["json", "markdown"],
        default="markdown",
        help="Output format",
    )

    args = parser.parse_args()

    # Parse PR title if provided
    package_info = {}
    if args.pr_title:
        parsed = parse_pr_title(args.pr_title)
        if parsed:
            package_info = parsed
        else:
            print("Warning: Could not parse PR title", file=sys.stderr)
            package_info = {
                "package": "unknown",
                "old_version": "unknown",
                "new_version": "unknown",
                "bump_type": VersionBump.UNKNOWN,
            }

    # Run security scan if requested
    security_results = {"success": True, "vulnerabilities": [], "error": None}
    if args.scan:
        security_results = run_pip_audit(args.requirements)

    # Calculate risk
    initial_risk = get_initial_risk_level(package_info.get("bump_type", VersionBump.UNKNOWN))
    has_vulns = len(security_results.get("vulnerabilities", [])) > 0
    ci_failed = args.ci_status == "failure"

    # Determine vulnerability severity from scan results
    vuln_severity = None
    if has_vulns:
        vuln_severity = extract_vulnerability_severity(
            security_results.get("vulnerabilities", [])
        )

    final_risk = calculate_final_risk(
        initial_risk,
        has_vulns,
        vuln_severity,
        ci_failed,
    )

    # Generate output
    if args.output == "json":
        output = {
            "package_info": package_info,
            "security_results": security_results,
            "ci_status": args.ci_status,
            "risk": {
                "initial": initial_risk,
                "final": final_risk,
            },
        }
        print(json.dumps(output, indent=2))
    else:
        report = generate_assessment_report(
            package_info,
            security_results,
            args.ci_status,
            final_risk,
        )
        print(report)


if __name__ == "__main__":
    main()
