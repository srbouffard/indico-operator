# Dependency Update Validator Agent

This GitHub Copilot Workspace agent validates dependency updates in Renovate PRs for the Indico Operator charm.

## Overview

The Dependency Update Validator Agent automatically assesses the risk of dependency updates by:
- Classifying version bumps (patch/minor/major)
- Running security scans for vulnerabilities
- Monitoring CI/CD check status
- Generating risk assessments with actionable recommendations

## Usage

### Activation

The agent can be invoked in several ways:

1. **Automatically** - When Renovate creates a PR updating dependencies
2. **Via Label** - Add `agent:dependency-updater` or `renovate` label to a PR
3. **Via Mention** - Comment with `@dependency-validator` in a PR
4. **Via File Changes** - On PRs modifying:
   - `requirements.txt`
   - `pyproject.toml`
   - `lib/charms/*`
   - `*rockcraft.yaml`

### Agent Capabilities

The agent performs the following steps:

1. **Parse PR Information** - Extracts package name and version changes from PR title
2. **Classify Version Bump** - Determines if it's a patch, minor, or major version change
3. **Security Scanning** - Runs `pip-audit` and checks GitHub Advisory Database
4. **CI Monitoring** - Waits for and checks status of required CI checks
5. **Risk Assessment** - Calculates final risk level based on all factors
6. **Recommendation** - Posts assessment comment with actionable next steps

### Risk Levels

| Risk Level | Criteria | Action |
|------------|----------|--------|
| 🟢 **Low** | Patch bump, no vulnerabilities, CI passed | Safe to merge after review |
| 🟡 **Medium** | Minor bump, no/low vulnerabilities, CI passed | Review required before merge |
| 🟠 **High** | Major bump, medium vulnerabilities, or CI failures | Careful review and staging testing |
| 🔴 **Critical** | Critical vulnerabilities or multiple high risks | Do not merge - issues must be resolved |

## Supporting Tools

### Validation Script

The agent uses `.github/scripts/validate_dependency.py` to perform dependency analysis.

#### Command-Line Usage

```bash
# Parse PR title and generate assessment
python3 .github/scripts/validate_dependency.py \
  --pr-title "Update pydantic from 1.10.24 to 1.10.25" \
  --ci-status success

# Run security scan on requirements.txt
python3 .github/scripts/validate_dependency.py \
  --pr-title "Update ops from 2.0.0 to 3.0.0" \
  --requirements requirements.txt \
  --scan \
  --ci-status pending

# Generate JSON output for automation
python3 .github/scripts/validate_dependency.py \
  --pr-title "Update dependency requests to 2.31.0" \
  --output json
```

#### Script Options

- `--pr-title` - PR title to parse for package/version info
- `--requirements` - Path to requirements.txt file (default: requirements.txt)
- `--scan` - Run pip-audit security scan
- `--ci-status` - CI check status: success, failure, pending, none
- `--output` - Output format: markdown (default) or json

### Example Output

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

### Rollback Plan
If issues occur after merge:
\```bash
git revert <commit-sha>
\```
```

## Testing

Unit tests for the validation script are located in `tests/unit/test_validate_dependency.py`.

Run tests with:
```bash
python3 -m pytest tests/unit/test_validate_dependency.py -v
```

Or with tox:
```bash
tox -e unit -- tests/unit/test_validate_dependency.py
```

## Agent Constraints

The agent follows these important constraints:

- ✅ **Does** assess risk and provide recommendations
- ✅ **Does** run security scans and check CI status
- ✅ **Does** add labels to categorize PRs
- ❌ **Does NOT** auto-merge PRs
- ❌ **Does NOT** directly approve PRs
- ❌ **Does NOT** make code changes

## Risk Assessment Matrix

| Version Bump | Vulnerabilities | CI Status | Risk Level | Agent Action |
|--------------|----------------|-----------|------------|--------------|
| Patch | None | Pass | Low | Add `safe-to-merge` label |
| Patch | Low | Pass | Medium | Request review |
| Minor | None/Low | Pass | Medium | Request review |
| Minor | Medium | Pass | High | Request careful review |
| Major | Any | Pass | High | Request careful review |
| Any | Critical | Any | Critical | Add `needs-review`, block merge |
| Any | Any | Fail | High+ | Request careful review |

## Integration with Renovate

This agent is designed to work seamlessly with Renovate bot PRs. Renovate is configured via `renovate.json` in the repository root.

### Renovate Configuration

The repository's `renovate.json` configures:
- Auto-merge settings (enabled)
- Package rules for different dependency types
- Custom datasources for charmhub
- Regex managers for rockcraft.yaml and terraform files

The agent provides an additional safety layer by validating updates before auto-merge occurs.

## Maintenance

### Updating the Agent

The agent prompt is defined in `.github/agents/dependency-validator.md`. To modify the agent's behavior:

1. Edit the agent prompt file
2. Update the validation script if logic changes are needed
3. Add/update tests in `tests/unit/test_validate_dependency.py`
4. Test changes thoroughly before committing

### Adding New Security Checks

To add additional security checks:

1. Update `validate_dependency.py` with new check functions
2. Integrate checks into `calculate_final_risk()` function
3. Update risk matrix documentation
4. Add tests for new functionality

## Troubleshooting

### Agent Not Responding

1. Check that PR modifies one of the trigger files
2. Verify agent is properly invoked via label or mention
3. Check GitHub Copilot Workspace logs for errors

### Security Scan Failures

1. Ensure `pip-audit` can be installed in environment
2. Check that `requirements.txt` is valid
3. Verify network access to PyPI and GitHub Advisory Database

### Incorrect Risk Assessment

1. Review PR title format - must match expected patterns
2. Check that version strings are in valid semver format
3. Verify CI check names match expected values
4. Review agent logs for parsing errors

## Contributing

When contributing improvements to this agent:

1. Follow the existing code style
2. Add unit tests for new functionality
3. Update documentation
4. Test with real Renovate PRs when possible
5. Ensure security scanning continues to work

## License

Copyright 2025 Canonical Ltd. See LICENSE file for licensing details.
