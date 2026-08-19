<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-mingw/v3** was hardened automatically. 8 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Multiple ${{ }} expressions are interpolated directly inside run: shell script blocks, violating rule (a). In action.yml step 1 (id: setup): `${{ runner.os }}`, `${{ inputs.version }}` (twice), and `${{ inputs.platform }}` are embedded directly in the PowerShell run: block. In action.yml step 2: `${{ runner.os }}`, `${{ inputs.cc }}`, `${{ steps.setup.outputs.gcc }}`, and `${{ steps.setup.outputs.gxx }}` are embedded directly in the PowerShell run: block. In .github/workflows/test.yml (both 'test' and 'different_versions' jobs): `${{ steps.setup.outputs.gxx }}` is interpolated directly in a run: block. In .github/actions/check-cc/action.yml: `${{ inputs.version }}` is interpolated directly in a run: block. All of these allow an attacker to inject arbitrary shell commands by controlling the expression values.

Locations:

- `action.yml:33`
- `action.yml:34`
- `action.yml:35`
- `action.yml:39`
- `action.yml:155`
- `action.yml:158`
- `action.yml:175`
- `action.yml:176`
- `.github/workflows/test.yml:37`
- `.github/workflows/test.yml:63`
- `.github/actions/check-cc/action.yml:22`

### github-env-injection (severity: high)

In action.yml step 1 (id: setup), values derived from untrusted inputs are written to special GitHub environment files without sanitization. Specifically: (1) `${{ inputs.version }}` is directly interpolated into the script and used to construct `$mingw_version`, which influences the package installation path and ultimately `$mingw_bin`, which is written to `$env:GITHUB_PATH` via `echo $mingw_bin >> $env:GITHUB_PATH`. (2) `${{ inputs.platform }}` is directly interpolated and used to compute `$prefix`, `$gcc`, `$gxx`, and `$windres`, all of which are written to `$env:GITHUB_OUTPUT` (e.g., `echo "prefix=$prefix" >> $env:GITHUB_OUTPUT`). None of these writes are preceded by the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker-controlled newline in any of these values could inject arbitrary key=value pairs into GITHUB_OUTPUT or GITHUB_PATH.

Locations:

- `action.yml:109`
- `action.yml:122`
- `action.yml:123`
- `action.yml:124`
- `action.yml:125`

### missing-permissions (severity: medium)

The workflow file .github/workflows/test.yml has no top-level `permissions:` key, and neither of its jobs ('test' or 'different_versions') defines a job-level `permissions:` block. This means the workflow runs with the default (broad) GitHub token permissions, violating the principle of least privilege.

Locations:

- `.github/workflows/test.yml:1`

### unpinned-uses (severity: high)

The workflow file .github/workflows/test.yml references external actions using mutable tag refs instead of full 40-character commit SHAs. Unpinned references are vulnerable to supply-chain attacks if the tag is moved or the upstream repository is compromised. Failing references: `actions/checkout@v6` (line 26, line 30 in different_versions job) and `egor-tensin/cleanup-path@v4` (line 28, line 33 in different_versions job).

Locations:

- `.github/workflows/test.yml:26`
- `.github/workflows/test.yml:28`
- `.github/workflows/test.yml:51`
- `.github/workflows/test.yml:53`

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

**Fixes applied:** script-injection, github-env-injection, missing-permissions, unpinned-uses, static-inline-injection

**Notes:**

Fixed all findings across action.yml, .github/workflows/test.yml, and .github/actions/check-cc/action.yml:

1. action.yml step 1 (setup): Moved ${{ runner.os }}, ${{ inputs.version }}, and ${{ inputs.platform }} to env: block as INPUT_RUNNER_OS, INPUT_VERSION, INPUT_PLATFORM; updated run: script to use $env: variables.

2. action.yml step 1 (github-env-injection): Added PowerShell sanitization using `-replace '[\r\n]', ''` before writing $mingw_bin to GITHUB_PATH and before writing prefix/gcc/gxx/windres to GITHUB_OUTPUT.

3. action.yml step 2: Moved ${{ runner.os }}, ${{ inputs.cc }}, ${{ steps.setup.outputs.gcc }}, ${{ steps.setup.outputs.gxx }} to env: block; updated run: script to use $env: variables.

4. .github/actions/check-cc/action.yml: Moved ${{ inputs.version }} to env: block as INPUT_VERSION; updated run: script to use $env:INPUT_VERSION.

5. .github/workflows/test.yml: Added top-level `permissions: {}` block; pinned actions/checkout@v6 to SHA df4cb1c069e1874edd31b4311f1884172cec0e10 and egor-tensin/cleanup-path@v4 to SHA cf0901d753db0bf4d15baf625a6fa537978b03a9 in both jobs; moved ${{ steps.setup.outputs.gxx }} to env: blocks in both 'Build foo.exe' steps.

