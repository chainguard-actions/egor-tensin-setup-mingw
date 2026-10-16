<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v3.0.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-mingw/v3.0.1** was hardened automatically. 6 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a): Direct expression interpolation in run: blocks. Step 1 (id: setup) in action.yml interpolates ${{ runner.os }}, ${{ inputs.version }} (twice), and ${{ inputs.platform }} directly inside a PowerShell run: block. The GitHub Actions template engine substitutes these values before PowerShell executes them, allowing an attacker-controlled input (e.g. inputs.version or inputs.platform) to inject arbitrary PowerShell code. Offending lines include:
  New-Variable os -Value '${{ runner.os }}' -Option Constant
  New-Variable mingw_version -Value '${{ inputs.version }}' -Option Constant
  New-Variable mingw_version_supplied -Value ('${{ inputs.version }}' -ne '') -Option Constant
  New-Variable x64 -Value ('${{ inputs.platform }}' -eq 'x64') -Option Constant

Locations:

- `action.yml:30`
- `action.yml:31`
- `action.yml:32`
- `action.yml:34`

### script-injection (severity: high)

Rule (a): Direct expression interpolation in run: blocks. Step 2 in action.yml interpolates ${{ runner.os }}, ${{ inputs.cc }}, ${{ steps.setup.outputs.gcc }}, and ${{ steps.setup.outputs.gxx }} directly inside a PowerShell run: block. The GitHub Actions template engine substitutes these values before PowerShell executes them, allowing attacker-controlled inputs or step outputs to inject arbitrary PowerShell code. Offending lines include:
  New-Variable os -Value '${{ runner.os }}' -Option Constant
  New-Variable cc -Value ('${{ inputs.cc }}' -eq '1') -Option Constant
  Link-Exe '${{ steps.setup.outputs.gcc }}' cc
  Link-Exe '${{ steps.setup.outputs.gxx }}' c++

Locations:

- `action.yml:121`
- `action.yml:125`
- `action.yml:149`
- `action.yml:150`

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

**Fixes applied:** script-injection, static-inline-injection

**Notes:**

Fixed all script injection findings in action.yml by moving ${{ }} expressions out of PowerShell run: blocks and into env: blocks. Step 1 (id: setup): moved ${{ runner.os }}, ${{ inputs.version }}, and ${{ inputs.platform }} to env: as RUNNER_OS_VAL, INPUT_VERSION, INPUT_PLATFORM respectively, and updated the PowerShell script to use $env:RUNNER_OS_VAL, $env:INPUT_VERSION, $env:INPUT_PLATFORM. Step 2: moved ${{ runner.os }}, ${{ inputs.cc }}, ${{ steps.setup.outputs.gcc }}, and ${{ steps.setup.outputs.gxx }} to env: as RUNNER_OS_VAL, INPUT_CC, SETUP_GCC, SETUP_GXX respectively, and updated the PowerShell script to use $env:RUNNER_OS_VAL, $env:INPUT_CC, $env:SETUP_GCC, $env:SETUP_GXX. All references use the correct PowerShell environment variable syntax ($env:VAR_NAME) since both steps use shell: pwsh.

### Iteration 2

**Fixes applied:** script-injection

**Notes:**

Fixed script injection in hardened/action/.github/actions/check-cc/action.yml: moved `${{ inputs.version }}` out of the PowerShell run: block and into an `env:` block as `INPUT_VERSION: ${{ inputs.version }}`. The script now reads the value safely via `$env:INPUT_VERSION` instead of directly interpolating the expression into the PowerShell source code. This prevents an attacker from injecting arbitrary PowerShell commands through a crafted version input.

