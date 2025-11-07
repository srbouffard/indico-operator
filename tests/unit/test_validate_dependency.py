"""Tests for the dependency validation script."""

import json
import sys
from pathlib import Path

# Add the scripts directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / ".github" / "scripts"))

import pytest

from validate_dependency import (
    RiskLevel,
    VersionBump,
    calculate_final_risk,
    classify_version_bump,
    generate_assessment_report,
    get_initial_risk_level,
    parse_pr_title,
    parse_version,
)


class TestVersionParsing:
    """Test version parsing functionality."""

    def test_parse_version_standard(self):
        """Test parsing standard semantic version."""
        major, minor, patch = parse_version("1.10.24")
        assert major == 1
        assert minor == 10
        assert patch == 24

    def test_parse_version_with_v_prefix(self):
        """Test parsing version with 'v' prefix."""
        major, minor, patch = parse_version("v2.3.4")
        assert major == 2
        assert minor == 3
        assert patch == 4

    def test_parse_version_invalid(self):
        """Test parsing invalid version raises ValueError."""
        with pytest.raises(ValueError):
            parse_version("invalid")


class TestVersionBumpClassification:
    """Test version bump classification."""

    def test_classify_patch_bump(self):
        """Test classification of patch version bump."""
        result = classify_version_bump("1.10.24", "1.10.25")
        assert result == VersionBump.PATCH

    def test_classify_minor_bump(self):
        """Test classification of minor version bump."""
        result = classify_version_bump("1.10.24", "1.11.0")
        assert result == VersionBump.MINOR

    def test_classify_major_bump(self):
        """Test classification of major version bump."""
        result = classify_version_bump("1.10.24", "2.0.0")
        assert result == VersionBump.MAJOR

    def test_classify_invalid_version(self):
        """Test classification with invalid version returns unknown."""
        result = classify_version_bump("invalid", "1.0.0")
        assert result == VersionBump.UNKNOWN


class TestPRTitleParsing:
    """Test PR title parsing."""

    def test_parse_standard_renovate_title(self):
        """Test parsing standard Renovate PR title."""
        title = "Update pydantic from 1.10.24 to 1.10.25"
        result = parse_pr_title(title)

        assert result is not None
        assert result["package"] == "pydantic"
        assert result["old_version"] == "1.10.24"
        assert result["new_version"] == "1.10.25"
        assert result["bump_type"] == VersionBump.PATCH

    def test_parse_dependency_format(self):
        """Test parsing alternative dependency format."""
        title = "Update dependency ops to 2.0.0"
        result = parse_pr_title(title)

        assert result is not None
        assert result["package"] == "ops"
        assert result["new_version"] == "2.0.0"

    def test_parse_unparseable_title(self):
        """Test parsing non-Renovate title returns None."""
        title = "Fix bug in authentication"
        result = parse_pr_title(title)

        assert result is None


class TestRiskCalculation:
    """Test risk level calculation."""

    def test_initial_risk_patch(self):
        """Test initial risk for patch bump is low."""
        risk = get_initial_risk_level(VersionBump.PATCH)
        assert risk == RiskLevel.LOW

    def test_initial_risk_minor(self):
        """Test initial risk for minor bump is medium."""
        risk = get_initial_risk_level(VersionBump.MINOR)
        assert risk == RiskLevel.MEDIUM

    def test_initial_risk_major(self):
        """Test initial risk for major bump is high."""
        risk = get_initial_risk_level(VersionBump.MAJOR)
        assert risk == RiskLevel.HIGH

    def test_final_risk_no_issues(self):
        """Test final risk with no vulnerabilities or CI failures."""
        risk = calculate_final_risk(
            RiskLevel.LOW,
            has_vulnerabilities=False,
            ci_failed=False,
        )
        assert risk == RiskLevel.LOW

    def test_final_risk_with_critical_vuln(self):
        """Test final risk escalates with critical vulnerability."""
        risk = calculate_final_risk(
            RiskLevel.LOW,
            has_vulnerabilities=True,
            vulnerability_severity="critical",
            ci_failed=False,
        )
        assert risk == RiskLevel.CRITICAL

    def test_final_risk_with_ci_failure(self):
        """Test final risk escalates with CI failure."""
        risk = calculate_final_risk(
            RiskLevel.LOW,
            has_vulnerabilities=False,
            ci_failed=True,
        )
        assert risk == RiskLevel.HIGH


class TestReportGeneration:
    """Test assessment report generation."""

    def test_generate_report_low_risk(self):
        """Test report generation for low risk scenario."""
        package_info = {
            "package": "pydantic",
            "old_version": "1.10.24",
            "new_version": "1.10.25",
            "bump_type": VersionBump.PATCH,
        }
        security_results = {
            "success": True,
            "vulnerabilities": [],
            "error": None,
        }

        report = generate_assessment_report(
            package_info,
            security_results,
            ci_status="success",
            final_risk=RiskLevel.LOW,
        )

        assert "🟢 Low" in report
        assert "pydantic" in report
        assert "1.10.24 → 1.10.25" in report
        assert "✅ No vulnerabilities found" in report
        assert "✅ All checks passed" in report
        assert "✅ Safe to merge after review" in report

    def test_generate_report_high_risk(self):
        """Test report generation for high risk scenario."""
        package_info = {
            "package": "requests",
            "old_version": "2.0.0",
            "new_version": "3.0.0",
            "bump_type": VersionBump.MAJOR,
        }
        security_results = {
            "success": True,
            "vulnerabilities": [
                {"name": "requests", "version": "2.0.0"},
            ],
            "error": None,
        }

        report = generate_assessment_report(
            package_info,
            security_results,
            ci_status="failure",
            final_risk=RiskLevel.HIGH,
        )

        assert "🟠 High" in report
        assert "requests" in report
        assert "⚠️ 1 vulnerabilities found" in report
        assert "❌ Some checks failed" in report
        assert "⚠️ Careful review required" in report
