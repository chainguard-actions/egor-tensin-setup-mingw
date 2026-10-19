<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v3.0.4

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-mingw/v3.0.4** was hardened automatically. 1 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): `${{ runner.os }}` is directly interpolated inside `run:` shell command strings in two steps of action.yml. Any `${{ ... }}` expression directly inside a `run:` block is a script-injection risk because the value is substituted into the shell script before the shell parses it. Offending lines in step 1 (setup): `$linux_host = '${{ runner.os }}' -eq 'Linux'` and `$windows_host = '${{ runner.os }}' -eq 'Windows'`. The same pattern repeats in step 2. These should be replaced with the environment variable `$env:RUNNER_OS` (already available as a pre-set GitHub Actions env var) to avoid template substitution into the shell script.

Locations:

- `action.yml:40`
- `action.yml:41`
- `action.yml:151`
- `action.yml:152`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection

**Notes:**

Replaced `'${{ runner.os }}'` with `$env:RUNNER_OS` in both PowerShell run blocks in action.yml. The RUNNER_OS environment variable is pre-set by GitHub Actions and contains the same value as `runner.os`, so the logic is preserved while eliminating the template substitution into the shell script. Changes were made in step 1 (setup, lines 40-41) and step 2 (lines 151-152), covering all four offending lines.

### Iteration 2

**Fixes applied:** github-env-injection

**Notes:**

Fixed github-env-injection in action.yml at line 130. Added sanitization of $mingw_bin before writing to $env:GITHUB_PATH using PowerShell's -replace operator: `$mingw_bin_safe = $mingw_bin -replace '[\r\n]', ''` followed by `echo $mingw_bin_safe >> $env:GITHUB_PATH`. This strips any newline characters that could be injected via the user-controlled inputs.platform value, preventing GITHUB_PATH injection attacks.

