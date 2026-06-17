<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v3.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `1`

Action **egor-tensin--setup-mingw/v3.0** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): Multiple GitHub Actions expressions are interpolated directly inside `run:` shell command strings in the first `run:` block (step id: setup). The expressions `${{ runner.os }}`, `${{ inputs.version }}` (twice), and `${{ inputs.platform }}` are substituted into the PowerShell script before the shell processes it. An attacker controlling `inputs.version` or `inputs.platform` can inject arbitrary PowerShell commands. For example: `New-Variable mingw_version -Value '${{ inputs.version }}' -Option Constant` and `New-Variable x64 -Value ('${{ inputs.platform }}' -eq 'x64') -Option Constant`.

Locations:

- `action.yml:35`
- `action.yml:36`
- `action.yml:37`
- `action.yml:40`

### script-injection (severity: high)

Sub-rule (a): Multiple GitHub Actions expressions are interpolated directly inside `run:` shell command strings in the second `run:` block (cc symlinks step). The expressions `${{ runner.os }}`, `${{ inputs.cc }}`, `${{ steps.setup.outputs.gcc }}`, and `${{ steps.setup.outputs.gxx }}` are substituted into the PowerShell script before the shell processes it. An attacker controlling `inputs.cc` can inject arbitrary PowerShell commands. For example: `New-Variable cc -Value ('${{ inputs.cc }}' -eq '1') -Option Constant` and `Link-Exe '${{ steps.setup.outputs.gcc }}' cc`.

Locations:

- `action.yml:142`
- `action.yml:146`
- `action.yml:169`
- `action.yml:170`

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

Fixed all script injection vulnerabilities in action.yml by moving ${{ }} expressions out of run: blocks and into env: blocks for both steps:

1. Setup step (id: setup): Added env: block with RUNNER_OS_VAL (${{ runner.os }}), INPUT_VERSION (${{ inputs.version }}), and INPUT_PLATFORM (${{ inputs.platform }}). Updated the PowerShell script to reference $env:RUNNER_OS_VAL, $env:INPUT_VERSION, and $env:INPUT_PLATFORM instead of inline expressions.

2. CC symlinks step: Added env: block with RUNNER_OS_VAL (${{ runner.os }}), INPUT_CC (${{ inputs.cc }}), SETUP_GCC (${{ steps.setup.outputs.gcc }}), and SETUP_GXX (${{ steps.setup.outputs.gxx }}). Updated the PowerShell script to reference $env:RUNNER_OS_VAL, $env:INPUT_CC, $env:SETUP_GCC, and $env:SETUP_GXX instead of inline expressions.

All remaining ${{ }} expressions in the file are in value: blocks (action output declarations) or env: blocks, neither of which are subject to shell injection.

