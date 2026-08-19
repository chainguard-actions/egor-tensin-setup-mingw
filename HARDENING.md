<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v2.1.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-mingw/v2.1.0** was hardened automatically. 10 finding(s) were identified and resolved across 3 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple run: blocks in action.yml directly interpolate GitHub Actions expressions inside PowerShell script strings. Step 1 (id: setup) uses '${{ runner.os }}', '${{ inputs.cygwin }}', '${{ inputs.platform }}', and '${{ inputs.static }}' directly in the shell command. Step 2 uses '${{ runner.os }}', '${{ inputs.cygwin }}', '${{ inputs.cc }}', '${{ steps.setup.outputs.gcc }}', and '${{ steps.setup.outputs.gxx }}' directly. Step 3 uses '${{ inputs.cygwin }}' and '${{ inputs.hardlinks }}' directly. These expressions are substituted by the Actions template engine before the shell sees them, allowing an attacker-controlled value to inject arbitrary PowerShell commands. Additionally, .github/workflows/test.yml has a run: block that interpolates '${{ steps.setup.outputs.gxx }}' directly into a PowerShell command string.

Locations:

- `action.yml:44`
- `action.yml:160`
- `action.yml:200`
- `.github/workflows/test.yml:36`
- `.github/workflows/test.yml:69`

### unpinned-uses (severity: high)

The workflow file .github/workflows/test.yml references external actions using mutable version tags instead of full 40-character commit SHAs. Failing references: 'actions/checkout@v3' (lines 24 and 57), 'egor-tensin/setup-cygwin@v4' (line 26), 'egor-tensin/cleanup-path@v3' (line 59). These tags can be moved to point to different (potentially malicious) commits without notice, enabling supply-chain attacks.

Locations:

- `.github/workflows/test.yml:24`
- `.github/workflows/test.yml:26`
- `.github/workflows/test.yml:57`
- `.github/workflows/test.yml:59`

### missing-permissions (severity: medium)

The workflow file .github/workflows/test.yml has no top-level 'permissions:' key, and neither of its two jobs ('cygwin' and 'test') defines a job-level 'permissions:' block. Without explicit permissions, the workflow inherits the repository's default token permissions, which may be overly broad.

Locations:

- `.github/workflows/test.yml:1`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cygwin }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:48`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.platform }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:51`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.static }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:52`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cygwin }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:186`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cc }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:189`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cygwin }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:220`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.hardlinks }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:221`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, static-inline-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed all findings across action.yml and .github/workflows/test.yml:

1. script-injection/static-inline-injection in action.yml: All three run: blocks had ${{ }} expressions moved to env: blocks. Step 1 (setup): RUNNER_OS, INPUT_CYGWIN, INPUT_PLATFORM, INPUT_STATIC. Step 2: RUNNER_OS, INPUT_CYGWIN, INPUT_CC, SETUP_GCC, SETUP_GXX. Step 3: INPUT_CYGWIN, INPUT_HARDLINKS. All PowerShell references updated to use $env:VAR_NAME.

2. script-injection in test.yml: Both 'Build foo.exe' steps that used '${{ steps.setup.outputs.gxx }}' directly in PowerShell were fixed by adding env: SETUP_GXX: ${{ steps.setup.outputs.gxx }} and referencing $env:SETUP_GXX in the script.

3. unpinned-uses in test.yml: Pinned all four action references to full SHAs: actions/checkout@v3 → @a37ce9120846195fa4ece8f58b268e6043cb2f26 (both occurrences), egor-tensin/setup-cygwin@v4 → @fca9069f92361187d4abfaa5d8a7490e435d8349, egor-tensin/cleanup-path@v3 → @8469525c8ee3eddabbd3487658621a6235b3c581.

4. missing-permissions in test.yml: Added 'permissions: {}' at the top level to explicitly restrict all token permissions.

### Iteration 2

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed script-injection in .github/actions/check-cc/action.yml by moving ${{ inputs.version }} into an env: block (INPUT_VERSION) and referencing it as $env:INPUT_VERSION in the PowerShell script. Fixed github-env-injection in action.yml by sanitizing all user-controlled values derived from inputs.platform before writing to $GITHUB_PATH and $GITHUB_OUTPUT using PowerShell's -replace '[\r\n]', '' to strip newlines: $safe_bin_dir for the cygwin GITHUB_PATH write, and $safe_prefix/$safe_gcc/$safe_gxx/$safe_windres for the four GITHUB_OUTPUT writes.

### Iteration 3

**Fixes applied:** script-injection

**Notes:**

Fixed both occurrences of unquoted `$env:SETUP_GXX` in PowerShell `run:` blocks in `.github/workflows/test.yml` (lines 39 and 71). Changed `& $env:SETUP_GXX` to `& "$env:SETUP_GXX"` in both the `cygwin` and `test` jobs. The `${{ steps.setup.outputs.gxx }}` expression was already correctly moved into the `env:` block; the remaining issue was that the PowerShell variable was not quoted when passed to the `&` call operator, allowing potential metacharacter injection.

