# Example: Using the Dependency Update Validator Agent

This file provides examples of how to use the Dependency Update Validator Agent.

## Using via GitHub Copilot Workspace

When a Renovate PR is created, you can invoke the agent in several ways:

### Option 1: Via Label
Add one of these labels to the PR:
- `agent:dependency-updater`
- `renovate`

### Option 2: Via Comment
Leave a comment mentioning the agent:
```
@dependency-validator please assess this update
```

### Option 3: Automatic Trigger
The agent automatically activates when PRs modify these files:
- `requirements.txt`
- `pyproject.toml` 
- `lib/charms/*`
- `*rockcraft.yaml`

## Using the Validation Script Directly

You can also use the validation script directly from the command line:

### Example 1: Assess a Patch Update
```bash
python3 .github/scripts/validate_dependency.py \
  --pr-title "Update pydantic from 1.10.24 to 1.10.25" \
  --ci-status success
```

Output:
```markdown
## 🤖 Dependency Update Assessment

**Package**: pydantic
**Version Change**: 1.10.24 → 1.10.25
**Bump Type**: Patch
**Risk Level**: 🟢 Low

### Security Scan
✅ No vulnerabilities found

### CI Status
✅ All checks passed

### Recommendation
✅ Safe to merge after review
```

### Example 2: Assess a Major Update with Security Scan
```bash
python3 .github/scripts/validate_dependency.py \
  --pr-title "Update ops from 2.0.0 to 3.0.0" \
  --requirements requirements.txt \
  --scan \
  --ci-status pending
```

### Example 3: Get JSON Output for Automation
```bash
python3 .github/scripts/validate_dependency.py \
  --pr-title "Update requests from 2.28.0 to 2.31.0" \
  --output json
```

Output:
```json
{
  "package_info": {
    "package": "requests",
    "old_version": "2.28.0",
    "new_version": "2.31.0",
    "bump_type": "minor"
  },
  "security_results": {
    "success": true,
    "vulnerabilities": [],
    "error": null
  },
  "ci_status": "none",
  "risk": {
    "initial": "medium",
    "final": "medium"
  }
}
```

## Sample Renovate PR Scenarios

### Scenario 1: Low Risk Patch Update

**PR Title**: "Update pydantic from 1.10.24 to 1.10.25"

**Agent Assessment**:
- Version Bump: Patch
- Initial Risk: Low
- Security Scan: No vulnerabilities
- CI Status: All checks passed
- Final Risk: Low
- Recommendation: Safe to merge after review

### Scenario 2: Medium Risk Minor Update

**PR Title**: "Update ops from 2.15.0 to 2.16.0"

**Agent Assessment**:
- Version Bump: Minor
- Initial Risk: Medium  
- Security Scan: No vulnerabilities
- CI Status: All checks passed
- Final Risk: Medium
- Recommendation: Review required before merge

### Scenario 3: High Risk Major Update

**PR Title**: "Update juju from 2.9.49 to 3.0.0"

**Agent Assessment**:
- Version Bump: Major
- Initial Risk: High
- Security Scan: No vulnerabilities
- CI Status: All checks passed
- Final Risk: High
- Recommendation: Careful review required - consider testing in staging

### Scenario 4: Critical - Vulnerability Found

**PR Title**: "Update requests from 2.25.0 to 2.31.0"

**Agent Assessment**:
- Version Bump: Minor
- Initial Risk: Medium
- Security Scan: 1 high severity vulnerability found
- CI Status: All checks passed
- Final Risk: Critical
- Recommendation: Do not merge - resolve vulnerability first

### Scenario 5: High Risk - CI Failure

**PR Title**: "Update indico from 3.3.6 to 3.4.0"

**Agent Assessment**:
- Version Bump: Minor
- Initial Risk: Medium
- Security Scan: No vulnerabilities
- CI Status: Integration tests failed
- Final Risk: High
- Recommendation: Investigate CI failures before merge

## Customizing Risk Assessment

You can customize the risk calculation by modifying the `calculate_final_risk()` function in `validate_dependency.py`:

```python
def calculate_final_risk(
    initial_risk: str,
    has_vulnerabilities: bool,
    vulnerability_severity: Optional[str] = None,
    ci_failed: bool = False,
) -> str:
    # Customize risk calculation logic here
    ...
```

## Integration with CI/CD

You can integrate the validation script into your CI/CD pipeline:

```yaml
name: Validate Dependencies
on:
  pull_request:
    paths:
      - 'requirements.txt'
      - 'pyproject.toml'

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run dependency validation
        run: |
          python3 .github/scripts/validate_dependency.py \
            --pr-title "${{ github.event.pull_request.title }}" \
            --requirements requirements.txt \
            --scan \
            --output json > validation-results.json
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: validation-results
          path: validation-results.json
```

## Troubleshooting

### Issue: Script not parsing PR title

**Solution**: Ensure PR title follows Renovate format:
- "Update [package] from X.Y.Z to A.B.C"
- "Update dependency [package] to vX.Y.Z"

### Issue: Security scan fails

**Solution**: Install pip-audit first:
```bash
pip install pip-audit
```

### Issue: CI status not detected

**Solution**: Pass CI status explicitly via `--ci-status` flag:
```bash
--ci-status success|failure|pending|none
```
