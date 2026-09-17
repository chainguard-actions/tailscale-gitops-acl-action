<!-- markdownlint-disable -->

# Hardening Report: tailscale--gitops-acl-action/v1.5.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **tailscale--gitops-acl-action/v1.5.1** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Direct expression interpolation in a `run:` block. In the 'Fetch ID token' step, `${{ inputs.audience }}` is interpolated directly into a shell command string inside a curl URL: `"${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${{ inputs.audience }}"`. The `${{ }}` substitution occurs before the shell parses the string, allowing an attacker-controlled value to inject shell metacharacters.

Locations:

- `action.yml:49`

### script-injection (severity: high)

Sub-rule (a): Direct expression interpolation in a `run:` block. In the 'Gitops pusher' step, `${{ inputs.policy-file }}` and `${{ inputs.action }}` are interpolated directly into the shell command: `go run tailscale.com/cmd/gitops-pusher@... "--policy-file=${{ inputs.policy-file }}" "${{ inputs.action }}"`. Even inside double-quoted shell arguments, `${{ }}` substitution happens at YAML template time before the shell sees the string, enabling injection of shell metacharacters via attacker-controlled inputs.

Locations:

- `action.yml:57`

### github-env-injection (severity: high)

In the 'Fetch ID token' step, `ID_TOKEN` is written to `$GITHUB_OUTPUT` without sanitization. The token value is fetched via curl from a URL that includes the untrusted `${{ inputs.audience }}` expression. No `printf '%s' ... | tr -d '\n\r'` sanitization step is applied before `echo "id_token=$ID_TOKEN" >> $GITHUB_OUTPUT`, allowing a newline-containing value to inject additional key-value pairs into the output file.

Locations:

- `action.yml:51`

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

Fixed all 6 findings in action.yml:
1. 'Fetch ID token' step: Moved `${{ inputs.audience }}` to env block as AUDIENCE, referenced as ${AUDIENCE} in the curl URL.
2. 'Fetch ID token' step: Added `printf '%s' "$ID_TOKEN" | tr -d '\n\r'` sanitization before writing to $GITHUB_OUTPUT to prevent newline injection. Also quoted $GITHUB_OUTPUT.
3. 'Gitops pusher' step: Moved `${{ inputs.policy-file }}` and `${{ inputs.action }}` to env block as POLICY_FILE and ACTION, referenced as ${POLICY_FILE} and ${ACTION} in the go run command.

