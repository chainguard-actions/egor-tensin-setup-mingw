<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v2.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-mingw/v2.2.0** was hardened automatically. 15 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The first run: step (id: setup) in action.yml directly interpolates multiple ${{ ... }} expressions inside a PowerShell shell command string. Affected expressions include: '${{ runner.os }}' (line 44), '${{ inputs.version }}' (lines 45–46), '${{ inputs.cygwin }}' (line 49), '${{ inputs.platform }}' (line 51), '${{ inputs.static }}' (line 52). Any ${{ ... }} expression interpolated directly in a run: block is a script-injection risk — an attacker-controlled value (e.g. inputs.version, inputs.platform) is substituted into the script before the shell ever sees it, allowing injection of arbitrary PowerShell code.

Locations:

- `action.yml:44`
- `action.yml:45`
- `action.yml:46`
- `action.yml:49`
- `action.yml:51`
- `action.yml:52`

### script-injection (severity: high)

Sub-rule (a): The second run: step in action.yml directly interpolates '${{ runner.os }}' (line 132), '${{ inputs.cygwin }}' (line 135), '${{ inputs.cc }}' (line 137), '${{ steps.setup.outputs.gcc }}' (line 155), and '${{ steps.setup.outputs.gxx }}' (line 156) inside a PowerShell shell command string. These expressions are substituted into the script before the shell executes it, enabling script injection via attacker-controlled inputs.

Locations:

- `action.yml:132`
- `action.yml:135`
- `action.yml:137`
- `action.yml:155`
- `action.yml:156`

### script-injection (severity: high)

Sub-rule (a): The third run: step in action.yml directly interpolates '${{ inputs.cygwin }}' and '${{ inputs.hardlinks }}' inside a PowerShell shell command string. These attacker-controlled inputs are substituted into the script before the shell executes it, enabling script injection.

Locations:

- `action.yml:163`
- `action.yml:164`

### script-injection (severity: high)

Sub-rule (a): Three 'Build foo.exe' run: steps in .github/workflows/test.yml directly interpolate '${{ steps.setup.outputs.gxx }}' inside a PowerShell shell command: `& '${{ steps.setup.outputs.gxx }}' -std=c++14 -o foo foo.cpp`. The steps.*.outputs.* context is workflow-controllable and must not be interpolated directly in a run: block.

Locations:

- `.github/workflows/test.yml:36`
- `.github/workflows/test.yml:68`
- `.github/workflows/test.yml:92`

### unpinned-uses (severity: high)

The workflow .github/workflows/test.yml references external actions using mutable version tags instead of immutable 40-character commit SHAs. Unpinned references: 'actions/checkout@v3' (used in all three jobs), 'egor-tensin/setup-cygwin@v4' (cygwin job), 'egor-tensin/cleanup-path@v3' (test and different_versions jobs). These tags can be moved to point to different, potentially malicious commits at any time.

Locations:

- `.github/workflows/test.yml:24`
- `.github/workflows/test.yml:26`
- `.github/workflows/test.yml:56`
- `.github/workflows/test.yml:58`
- `.github/workflows/test.yml:83`
- `.github/workflows/test.yml:85`

### missing-permissions (severity: medium)

The workflow .github/workflows/test.yml has no top-level 'permissions:' key and none of its three jobs (cygwin, test, different_versions) define job-level 'permissions:' blocks. Without explicit permissions, the workflow runs with the default token permissions, which may be overly broad (e.g. write access to repository contents). Explicit minimal permissions should be declared.

Locations:

- `.github/workflows/test.yml:1`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.version }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:50`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.version }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:51`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cygwin }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:54`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.platform }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:57`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.static }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:58`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cygwin }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:208`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cc }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:211`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cygwin }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:242`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.hardlinks }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:243`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, unpinned-uses, missing-permissions, static-inline-injection

**Notes:**

Fixed all findings in action.yml and .github/workflows/test.yml:

1. action.yml script-injection: Moved all ${{ }} expressions from run: blocks to env: blocks for all three composite steps. Step 1 (id: setup) uses INPUT_OS, INPUT_VERSION, INPUT_CYGWIN, INPUT_PLATFORM, INPUT_STATIC. Step 2 uses INPUT_OS, INPUT_CYGWIN, INPUT_CC, SETUP_GCC, SETUP_GXX. Step 3 uses INPUT_CYGWIN, INPUT_HARDLINKS. PowerShell scripts reference these via $env:VAR_NAME.

2. test.yml script-injection: All three 'Build foo.exe' steps now move ${{ steps.setup.outputs.gxx }} into an env: block as SETUP_GXX and reference it as $env:SETUP_GXX in the run: block.

3. test.yml unpinned-uses: Pinned actions/checkout@v3 to SHA a37ce9120846195fa4ece8f58b268e6043cb2f26, egor-tensin/setup-cygwin@v4 to SHA fca9069f92361187d4abfaa5d8a7490e435d8349, and egor-tensin/cleanup-path@v3 to SHA 8469525c8ee3eddabbd3487658621a6235b3c581.

4. test.yml missing-permissions: Added top-level `permissions: {}` block to restrict default token permissions.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in hardened/action/.github/actions/check-cc/action.yml: moved `${{ inputs.version }}` out of the `run:` shell string and into the step's `env:` block as `INPUT_VERSION`. The PowerShell script now reads the value via `$env:INPUT_VERSION` instead of directly interpolating the GitHub Actions expression, eliminating the risk of arbitrary PowerShell command injection.

