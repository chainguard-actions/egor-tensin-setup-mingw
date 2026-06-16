<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-mingw/v3** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple `${{ ... }}` expressions are interpolated directly inside `run:` shell (PowerShell) command strings in action.yml. This includes attacker-controllable inputs and other context values that flow through YAML template substitution before the shell processes them.

Step 1 (id: setup) offending lines:
- `New-Variable os -Value '${{ runner.os }}' -Option Constant`
- `New-Variable mingw_version -Value '${{ inputs.version }}' -Option Constant`
- `New-Variable mingw_version_supplied -Value ('${{ inputs.version }}' -ne '') -Option Constant`
- `New-Variable x64 -Value ('${{ inputs.platform }}' -eq 'x64') -Option Constant`

Step 2 offending lines:
- `New-Variable os -Value '${{ runner.os }}' -Option Constant`
- `New-Variable cc -Value ('${{ inputs.cc }}' -eq '1') -Option Constant`
- `Link-Exe '${{ steps.setup.outputs.gcc }}' cc`
- `Link-Exe '${{ steps.setup.outputs.gxx }}' c++`

An attacker controlling `inputs.version`, `inputs.platform`, or `inputs.cc` can inject arbitrary PowerShell commands. All `${{ ... }}` expressions must be moved to `env:` variables and referenced as `$ENV_VAR` in the script.

Locations:

- `action.yml:37`
- `action.yml:38`
- `action.yml:39`
- `action.yml:41`
- `action.yml:148`
- `action.yml:152`
- `action.yml:172`
- `action.yml:173`

### github-env-injection (severity: high)

Step 1 (id: setup) writes values derived from untrusted inputs to `$env:GITHUB_PATH` and `$env:GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`).

- `echo $mingw_bin >> $env:GITHUB_PATH` — `$mingw_bin` is derived from `$mingw` which depends on `$x64`, which is set from `${{ inputs.platform }}` interpolated directly into the script.
- `echo "prefix=$prefix" >> $env:GITHUB_OUTPUT` — `$prefix` is derived from `$x64` (from `inputs.platform`).
- `echo "gcc=$gcc" >> $env:GITHUB_OUTPUT` — `$gcc` is derived from `$prefix`.
- `echo "gxx=$gxx" >> $env:GITHUB_OUTPUT` — `$gxx` is derived from `$prefix`.
- `echo "windres=$windres" >> $env:GITHUB_OUTPUT` — `$windres` is derived from `$prefix`.

A newline injected via `inputs.platform` or `inputs.version` could add arbitrary key=value pairs to GITHUB_OUTPUT or arbitrary paths to GITHUB_PATH. Sanitization using `printf '%s' "$VAR" | tr -d '\n\r'` must be applied before every write.

Locations:

- `action.yml:136`
- `action.yml:141`
- `action.yml:142`
- `action.yml:143`
- `action.yml:144`

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

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all security findings in action.yml:

1. script-injection / static-inline-injection: Moved all ${{ ... }} expressions from run: shell blocks to env: blocks in both steps. Step 1 (setup) now uses INPUT_OS, INPUT_VERSION, INPUT_PLATFORM env vars; Step 2 now uses INPUT_OS, INPUT_CC, INPUT_GCC, INPUT_GXX env vars. All are referenced as $env:INPUT_* in PowerShell.

2. github-env-injection: Added sanitization using PowerShell's -replace '[\r\n]', '' on all values before writing to $env:GITHUB_PATH and $env:GITHUB_OUTPUT, preventing newline injection attacks.

Test files under tests/ were not modified per instructions.

