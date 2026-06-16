<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v2.2.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-mingw/v2.2.0** was hardened automatically. 11 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Multiple `${{ }}` expressions are directly interpolated into PowerShell `run:` shell scripts across all three steps. The GitHub Actions template engine substitutes these values before the shell parses the script, so a malicious input value containing PowerShell metacharacters (e.g., `'; Invoke-Expression ...; '`) can break out of the string context and execute arbitrary commands.

Step 1 (id: setup) offending lines include:
  `New-Variable os -Value '${{ runner.os }}' -Option Constant`
  `New-Variable mingw_version -Value '${{ inputs.version }}' -Option Constant`
  `New-Variable mingw_version_supplied -Value ('${{ inputs.version }}' -ne '') -Option Constant`
  `New-Variable cygwin_host -Value ('${{ inputs.cygwin }}' -eq '1') -Option Constant`
  `New-Variable x64 -Value ('${{ inputs.platform }}' -eq 'x64') -Option Constant`
  `New-Variable static_workaround -Value ('${{ inputs.static }}' -eq '1') -Option Constant`

Step 2 offending lines include:
  `New-Variable os -Value '${{ runner.os }}' -Option Constant`
  `New-Variable cygwin_host -Value ('${{ inputs.cygwin }}' -eq '1') -Option Constant`
  `New-Variable cc -Value ('${{ inputs.cc }}' -eq '1') -Option Constant`
  `Link-Exe '${{ steps.setup.outputs.gcc }}' cc`
  `Link-Exe '${{ steps.setup.outputs.gxx }}' c++`

Step 3 offending lines include:
  `New-Variable cygwin_host -Value ('${{ inputs.cygwin }}' -eq '1') -Option Constant`
  `New-Variable hardlinks -Value ('${{ inputs.hardlinks }}' -eq '1') -Option Constant`

All inputs should be passed via `env:` variables and referenced as PowerShell environment variables (e.g., `$env:INPUT_VERSION`) rather than being interpolated directly with `${{ }}`.

Locations:

- `action.yml:49`
- `action.yml:50`
- `action.yml:51`
- `action.yml:54`
- `action.yml:57`
- `action.yml:58`
- `action.yml:176`
- `action.yml:178`
- `action.yml:180`
- `action.yml:200`
- `action.yml:201`
- `action.yml:206`
- `action.yml:207`

### github-env-injection (severity: high)

Step 1 (id: setup) writes values derived from user-controlled inputs to `$GITHUB_PATH` and `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`).

- `echo $bin_dir >> $env:GITHUB_PATH`: `$bin_dir` is computed from `$prefix`, which is derived from `${{ inputs.platform }}`. A newline embedded in `inputs.platform` could inject an arbitrary path entry into GITHUB_PATH.
- `echo $mingw_bin >> $env:GITHUB_PATH`: `$mingw_bin` is similarly derived from `inputs.platform` via `$x64` → `$mingw` → `$mingw_root` → `$mingw_bin`.
- `echo "prefix=$prefix" >> $env:GITHUB_OUTPUT`: `$prefix` is derived from `inputs.platform`; a newline could inject arbitrary key=value pairs into GITHUB_OUTPUT.
- `echo "gcc=$gcc" >> $env:GITHUB_OUTPUT`: `$gcc` is `$prefix + '-gcc'`, same taint.
- `echo "gxx=$gxx" >> $env:GITHUB_OUTPUT`: `$gxx` is `$prefix + '-g++'`, same taint.
- `echo "windres=$windres" >> $env:GITHUB_OUTPUT`: same taint.

None of these writes are preceded by the required sanitization pipeline.

Locations:

- `action.yml:120`
- `action.yml:143`
- `action.yml:163`
- `action.yml:164`
- `action.yml:165`
- `action.yml:166`

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

**Fixes applied:** script-injection, github-env-injection, static-inline-injection

**Notes:**

Fixed all three steps in action.yml:
1. Step 1 (setup): Added env: block with INPUT_OS, INPUT_VERSION, INPUT_CYGWIN, INPUT_PLATFORM, INPUT_STATIC. Replaced all ${{ }} expressions in run: with $env:INPUT_* PowerShell references. Added -replace '[\r\n]', '' sanitization for all values written to $GITHUB_PATH and $GITHUB_OUTPUT.
2. Step 2 (cc/c++ linking): Added env: block with INPUT_OS, INPUT_CYGWIN, INPUT_CC, INPUT_GCC, INPUT_GXX. Replaced all ${{ }} expressions including steps.setup.outputs.gcc and steps.setup.outputs.gxx with $env:INPUT_GCC and $env:INPUT_GXX.
3. Step 3 (hardlinks): Added env: block with INPUT_CYGWIN and INPUT_HARDLINKS. Replaced all ${{ }} expressions with $env:INPUT_* references.
All ${{ }} expressions now only appear in the outputs: section (legitimate) and env: blocks (safe), never directly in run: shell scripts.

