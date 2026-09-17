<!-- markdownlint-disable -->

# Hardening Report: tailscale--gitops-acl-action/v1.5.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **tailscale--gitops-acl-action/v1.5.2** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): In the 'Fetch ID token' step, the expression `${{ inputs.audience }}` is directly interpolated into the `run:` shell command string inside a URL argument: `"${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${{ inputs.audience }}"`. This allows an attacker-controlled input to inject arbitrary shell metacharacters before the shell ever sees the command.

Locations:

- `action.yml:50`

### script-injection (severity: high)

Rule (a): In the 'Gitops pusher' step, two inputs are directly interpolated into the `run:` shell command string: `"--policy-file=${{ inputs.policy-file }}"` and `"${{ inputs.action }}"`. Although other inputs are safely routed through `env:`, these two are embedded directly in the shell command, allowing an attacker-controlled input to inject arbitrary shell commands.

Locations:

- `action.yml:62`

### github-env-injection (severity: high)

In the 'Fetch ID token' step, the variable `$ID_TOKEN` (derived from a curl response whose URL includes the untrusted `${{ inputs.audience }}`) is written directly to `$GITHUB_OUTPUT` via `echo "id_token=$ID_TOKEN" >> $GITHUB_OUTPUT` without the required sanitization step (`printf '%s' "$ID_TOKEN" | tr -d '\n\r'`). A newline embedded in the token value could inject additional key=value pairs into the output.

Locations:

- `action.yml:52`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.audience }}" appears directly in run: block of step "Fetch ID token"; move to env: map

Locations:

- `action.yml:50`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.policy-file }}" appears directly in run: block of step "Gitops pusher"; move to env: map

Locations:

- `action.yml:65`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.action }}" appears directly in run: block of step "Gitops pusher"; move to env: map

Locations:

- `action.yml:65`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all 6 findings in hardened/action/action.yml:
1. 'Fetch ID token' step: moved `${{ inputs.audience }}` out of the run: shell string into an env: block (AUDIENCE), and referenced it as ${AUDIENCE} in the curl URL.
2. 'Fetch ID token' step: sanitized ID_TOKEN before writing to GITHUB_OUTPUT using `safe_token=$(printf '%s' "$ID_TOKEN" | tr -d '\n\r')` to prevent newline injection.
3. 'Gitops pusher' step: moved `${{ inputs.policy-file }}` and `${{ inputs.action }}` out of the run: shell string into the env: block as INPUT_POLICY_FILE and INPUT_ACTION respectively, referenced as shell variables in the go run command.

