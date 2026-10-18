<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v3.0.3

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-mingw/v3.0.3** was hardened automatically. 2 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The expression `${{ runner.os }}` is interpolated directly inside a `run:` shell command string in the first composite action step. Any `${{ ... }}` expression inside a `run:` block undergoes YAML template substitution before the shell processes it, making it a script-injection risk. Offending lines: `$linux_host = '${{ runner.os }}' -eq 'Linux'` and `$windows_host = '${{ runner.os }}' -eq 'Windows'`. These should be replaced with the environment variable `$env:RUNNER_OS` (already available as a pre-set GitHub Actions env var) to avoid direct expression interpolation.

Locations:

- `action.yml:37`
- `action.yml:38`

### script-injection (severity: high)

Sub-rule (a): The expression `${{ runner.os }}` is interpolated directly inside a `run:` shell command string in the second composite action step. Offending lines: `$linux_host = '${{ runner.os }}' -eq 'Linux'` and `$windows_host = '${{ runner.os }}' -eq 'Windows'`. These should be replaced with `$env:RUNNER_OS` to avoid direct expression interpolation in the run block.

Locations:

- `action.yml:130`
- `action.yml:131`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection

**Notes:**

Replaced all four occurrences of `${{ runner.os }}` (two in each of the two composite action steps) with `$env:RUNNER_OS` in hardened/action/action.yml. The `RUNNER_OS` environment variable is automatically set by the GitHub Actions runner and is safe to use directly in PowerShell (pwsh) run blocks without YAML template interpolation, eliminating the script injection risk.

