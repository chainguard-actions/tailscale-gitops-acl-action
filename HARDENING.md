<!-- markdownlint-disable -->

# Hardening Report: tailscale--gitops-acl-action/v1.5.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **tailscale--gitops-acl-action/v1.5.0** was hardened automatically. 6 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): `${{ inputs.audience }}` is interpolated directly inside a `run:` shell command string in the 'Fetch ID token' step. An attacker-controlled audience value is embedded into a curl URL before the shell ever sees it, enabling command injection. Offending line: `ID_TOKEN=$(curl -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${{ inputs.audience }}" | jq -r '.value')`

Locations:

- `action.yml:49`

### script-injection (severity: high)

Rule (a): `${{ inputs.policy-file }}` and `${{ inputs.action }}` are interpolated directly inside a `run:` shell command string in the 'Gitops pusher' step. These attacker-controlled values are embedded directly into the go run command before the shell processes them, enabling command injection. Offending line: `run: go run tailscale.com/cmd/gitops-pusher@... "--policy-file=${{ inputs.policy-file }}" "${{ inputs.action }}"`

Locations:

- `action.yml:63`

### github-env-injection (severity: high)

The 'Fetch ID token' step writes `$ID_TOKEN` to `$GITHUB_OUTPUT` without sanitization. `ID_TOKEN` is derived from a curl response whose URL is constructed using the untrusted `${{ inputs.audience }}` value. No `printf '%s' ... | tr -d '\n\r'` sanitization is applied before the write. A newline injected into the token value could allow an attacker to inject arbitrary key=value pairs into `$GITHUB_OUTPUT`. Offending line: `echo "id_token=$ID_TOKEN" >> $GITHUB_OUTPUT`

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
1. 'Fetch ID token' step: moved `${{ inputs.audience }}` to env: block as AUDIENCE, referenced as ${AUDIENCE} in the curl URL.
2. 'Fetch ID token' step: sanitized ID_TOKEN before writing to $GITHUB_OUTPUT using `printf '%s' "$ID_TOKEN" | tr -d '\n\r'` and quoted $GITHUB_OUTPUT.
3. 'Gitops pusher' step: moved `${{ inputs.policy-file }}` and `${{ inputs.action }}` into the existing env: block as TS_POLICY_FILE and TS_ACTION, referenced as ${TS_POLICY_FILE} and ${TS_ACTION} in the go run command. The two env: blocks were merged into one valid YAML block.

### Iteration 1

**Fixes applied:** script-injection

**Notes:**

Fixed three unquoted ${{ }} expressions in env: blocks in action.yml: (1) AUDIENCE: "${{ inputs.audience }}" in the 'Fetch ID token' step (line 46), (2) TS_POLICY_FILE: "${{ inputs.policy-file }}" and (3) TS_ACTION: "${{ inputs.action }}" in the 'Gitops pusher' step (lines 57-58). Added YAML double-quotes around all three expressions to prevent YAML parsing issues with attacker-controlled values containing shell metacharacters.

