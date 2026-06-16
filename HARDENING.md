<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v2.1.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-mingw/v2.1.0** was hardened automatically. 9 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple `run:` blocks in action.yml directly interpolate `${{ inputs.* }}` and `${{ runner.os }}` expressions inside PowerShell script strings. GitHub Actions performs YAML template substitution before the shell executes the script, so a caller-supplied input value containing PowerShell metacharacters (quotes, semicolons, command-substitution syntax, etc.) can inject arbitrary PowerShell commands.

Step 1 (id: setup): `New-Variable os -Value '${{ runner.os }}' -Option Constant`, `New-Variable cygwin_host -Value ('${{ inputs.cygwin }}' -eq '1') -Option Constant`, `New-Variable x64 -Value ('${{ inputs.platform }}' -eq 'x64') -Option Constant`, `New-Variable static_workaround -Value ('${{ inputs.static }}' -eq '1') -Option Constant`.

Step 2: `New-Variable os -Value '${{ runner.os }}' -Option Constant`, `New-Variable cygwin_host -Value ('${{ inputs.cygwin }}' -eq '1') -Option Constant`, `New-Variable cc -Value ('${{ inputs.cc }}' -eq '1') -Option Constant`, `Link-Exe '${{ steps.setup.outputs.gcc }}' cc`, `Link-Exe '${{ steps.setup.outputs.gxx }}' c++`.

Step 3: `New-Variable cygwin_host -Value ('${{ inputs.cygwin }}' -eq '1') -Option Constant`, `New-Variable hardlinks -Value ('${{ inputs.hardlinks }}' -eq '1') -Option Constant`.

All `inputs.*` values are caller-controlled and must be passed via environment variables and referenced as `$env:VAR` rather than interpolated directly as `${{ inputs.* }}`.

Locations:

- `action.yml:45`
- `action.yml:48`
- `action.yml:51`
- `action.yml:52`
- `action.yml:132`
- `action.yml:135`
- `action.yml:137`
- `action.yml:158`
- `action.yml:159`
- `action.yml:164`
- `action.yml:165`

### github-env-injection (severity: high)

The first `run:` block (step id: setup) writes values derived from caller-controlled inputs to `$env:GITHUB_PATH` and `$env:GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`).

1. `echo $bin_dir >> $env:GITHUB_PATH` — `$bin_dir` is computed via `cygpath.exe` from `$prefix`, which is derived from `${{ inputs.platform }}` (caller-controlled). An attacker can inject newlines to poison GITHUB_PATH.

2. `echo $mingw_bin >> $env:GITHUB_PATH` — `$mingw_bin` is derived from `$mingw_root` which depends on `$prefix` (from `${{ inputs.platform }}`). Same risk.

3. `echo "prefix=$prefix" >> $env:GITHUB_OUTPUT`, `echo "gcc=$gcc" >> $env:GITHUB_OUTPUT`, `echo "gxx=$gxx" >> $env:GITHUB_OUTPUT`, `echo "windres=$windres" >> $env:GITHUB_OUTPUT` — all values are derived from `${{ inputs.platform }}` without sanitization, allowing newline injection to set arbitrary GITHUB_OUTPUT key-value pairs.

Locations:

- `action.yml:100`
- `action.yml:118`
- `action.yml:124`
- `action.yml:125`
- `action.yml:126`
- `action.yml:127`

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

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all three steps in action.yml:

1. script-injection / static-inline-injection: Moved all ${{ inputs.* }} and ${{ runner.os }} expressions out of run: blocks into env: blocks for each step. In the PowerShell scripts, these are now referenced as $env:INPUT_OS, $env:INPUT_CYGWIN, $env:INPUT_PLATFORM, $env:INPUT_STATIC, $env:INPUT_CC, $env:INPUT_GCC, $env:INPUT_GXX, $env:INPUT_HARDLINKS.

2. github-env-injection: Added PowerShell -replace '[\r\n]', '' sanitization for all values written to $env:GITHUB_PATH ($bin_dir → $safe_bin_dir, $mingw_bin → $safe_mingw_bin) and $env:GITHUB_OUTPUT ($prefix → $safe_prefix, $gcc → $safe_gcc, $gxx → $safe_gxx, $windres → $safe_windres) to prevent newline injection attacks.

