<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v3.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-mingw/v3.0** was hardened automatically. 8 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple ${{ }} expressions are directly interpolated inside run: shell command strings in action.yml. Step 1 (id: setup) uses '${{ runner.os }}', '${{ inputs.version }}' (twice), and '${{ inputs.platform }}' directly in PowerShell code. Step 2 uses '${{ runner.os }}', '${{ inputs.cc }}', '${{ steps.setup.outputs.gcc }}', and '${{ steps.setup.outputs.gxx }}' directly in PowerShell code. These values are substituted by the Actions runner before the shell ever sees them, allowing an attacker-controlled input (e.g. inputs.version, inputs.platform, inputs.cc) to inject arbitrary PowerShell commands.

Locations:

- `action.yml:32`
- `action.yml:33`
- `action.yml:34`
- `action.yml:37`
- `action.yml:155`
- `action.yml:158`
- `action.yml:180`
- `action.yml:181`

### script-injection (severity: high)

Sub-rule (a): The 'Build foo.exe' run: step in the workflow directly interpolates '${{ steps.setup.outputs.gxx }}' inside a PowerShell shell command: `& '${{ steps.setup.outputs.gxx }}' -std=c++14 -o foo foo.cpp`. The expression is substituted before the shell parses the command, so a malicious value in steps.setup.outputs.gxx could inject arbitrary commands.

Locations:

- `.github/workflows/test.yml:35`

### permissions (severity: medium)

missing-permissions: The workflow file has no top-level permissions: key, and neither the 'test' job nor the 'different_versions' job defines a job-level permissions: block. Without explicit permissions, the GITHUB_TOKEN defaults to broad write access on many repository events (push, pull_request, workflow_dispatch), violating the principle of least privilege.

Locations:

- `.github/workflows/test.yml:1`

### unpinned-uses (severity: high)

Two external actions are referenced by mutable tag refs instead of immutable 40-character SHA digests, making the workflow vulnerable to supply-chain attacks if the tag is moved: (1) 'uses: actions/checkout@v6' — tag ref 'v6'; (2) 'uses: egor-tensin/cleanup-path@v4' — tag ref 'v4'. These appear in both the 'test' and 'different_versions' jobs. They should be pinned to full commit SHAs, e.g. actions/checkout@<40-hex-sha>.

Locations:

- `.github/workflows/test.yml:22`
- `.github/workflows/test.yml:24`
- `.github/workflows/test.yml:50`
- `.github/workflows/test.yml:51`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.version }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:38`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.version }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:39`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.platform }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:44`

### static-inline-injection (severity: high)

shell injection: expression "${{ inputs.cc }}" appears directly in run: block of step ""; move to env: map

Locations:

- `action.yml:168`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, permissions, unpinned-uses, static-inline-injection

**Notes:**

Fixed all findings:
1. action.yml script injection: Moved all ${{ runner.os }}, ${{ inputs.version }}, ${{ inputs.platform }}, ${{ inputs.cc }}, ${{ steps.setup.outputs.gcc }}, ${{ steps.setup.outputs.gxx }} expressions from run: shell code into env: blocks. PowerShell code now references them via $env:RUNNER_OS, $env:INPUT_VERSION, $env:INPUT_PLATFORM, $env:INPUT_CC, $env:SETUP_GCC, $env:SETUP_GXX.
2. test.yml script injection: Moved ${{ steps.setup.outputs.gxx }} to env: block (SETUP_GXX) in both 'Build foo.exe' steps, referenced as $env:SETUP_GXX.
3. test.yml permissions: Added top-level 'permissions: {}' to enforce least privilege.
4. test.yml unpinned-uses: Pinned actions/checkout@v6 to SHA d23441a48e516b6c34aea4fa41551a30e30af803 and egor-tensin/cleanup-path@v4 to SHA cf0901d753db0bf4d15baf625a6fa537978b03a9 in both jobs.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in `.github/actions/check-cc/action.yml` (line 20). Moved `${{ inputs.version }}` out of the PowerShell `run:` script body into an `env:` block (`INPUT_VERSION: ${{ inputs.version }}`). Updated the script to read the value via `$env:INPUT_VERSION` instead of the direct template interpolation `'${{ inputs.version }}'`. This prevents attacker-controlled input from breaking out of the string literal and executing arbitrary PowerShell commands.

