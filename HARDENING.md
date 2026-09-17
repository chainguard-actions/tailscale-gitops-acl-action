<!-- markdownlint-disable -->

# Hardening Report: tailscale--gitops-acl-action/v1.4.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **tailscale--gitops-acl-action/v1.4.0** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a) violation: Two `${{ inputs.* }}` expressions are directly interpolated inside a `run:` shell command string on line 50. The GitHub Actions template engine substitutes these values before the shell parses the command, so an attacker-controlled input can inject arbitrary shell metacharacters. Offending line: `run: go run tailscale.com/cmd/gitops-pusher@... "--policy-file=${{ inputs.policy-file }}" "${{ inputs.action }}"`

Fix: Move the inputs into `env:` variables and reference them as quoted shell variables, e.g.:
```yaml
env:
  POLICY_FILE: "${{ inputs.policy-file }}"
  ACTION: "${{ inputs.action }}"
run: go run tailscale.com/cmd/gitops-pusher@... "--policy-file=$POLICY_FILE" "$ACTION"
```

Locations:

- `action.yml:50`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.policy-file }}" appears directly in run: block of step "Gitops pusher"; move to env: map

Locations:

- `action.yml:53`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.action }}" appears directly in run: block of step "Gitops pusher"; move to env: map

Locations:

- `action.yml:53`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, static-inline-injection

**Notes:**

Moved `${{ inputs.policy-file }}` and `${{ inputs.action }}` from the `run:` shell command string into the `env:` block as `POLICY_FILE` and `ACTION` environment variables respectively. The `run:` command now safely references these as `"--policy-file=$POLICY_FILE"` and `"$ACTION"`, preventing shell injection via GitHub Actions template substitution.

