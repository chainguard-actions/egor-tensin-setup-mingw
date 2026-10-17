<!-- markdownlint-disable -->

# Hardening Report: egor-tensin--setup-mingw/v3.0.2

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **egor-tensin--setup-mingw/v3.0.2** was hardened automatically. 3 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): `${{ runner.os }}` is directly interpolated inside the `run:` shell command string in step 1 (id: setup). Any `${{ ... }}` expression inside a `run:` block is a script-injection risk because YAML template substitution occurs before the shell ever sees the value. Offending lines: `$linux_host = '${{ runner.os }}' -eq 'Linux'` and `$windows_host = '${{ runner.os }}' -eq 'Windows'`. These should be replaced with the `$env:RUNNER_OS` environment variable reference instead.

Locations:

- `action.yml:37`
- `action.yml:38`

### script-injection (severity: high)

Sub-rule (a): `${{ runner.os }}` is directly interpolated inside the `run:` shell command string in step 2 (the cc/link step). Same issue as step 1 — YAML template substitution injects the value before the shell parses it. Offending lines: `$linux_host = '${{ runner.os }}' -eq 'Linux'` and `$windows_host = '${{ runner.os }}' -eq 'Windows'`. These should use `$env:RUNNER_OS` instead.

Locations:

- `action.yml:148`
- `action.yml:149`

### github-env-injection (severity: high)

Step 1 (id: setup) writes values derived from the untrusted input `inputs.platform` (mapped to `$env:ARG_PLATFORM`) to `$GITHUB_PATH` and `$GITHUB_OUTPUT` without sanitization. Specifically: (1) `echo $mingw_bin >> $env:GITHUB_PATH` — `$mingw_bin` is computed from `$mingw_install` which is derived from `$mingw` which comes from `$x64 = $env:ARG_PLATFORM -eq 'x64'`; (2) `echo "prefix=$prefix" >> $env:GITHUB_OUTPUT` — `$prefix` is selected based on `$env:ARG_PLATFORM`; (3) `echo "gcc=$gcc" >> $env:GITHUB_OUTPUT` and `echo "gxx=$gxx" >> $env:GITHUB_OUTPUT` — both derived from `$prefix`. None of these writes are preceded by the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). An attacker-controlled `inputs.platform` value containing newlines could inject arbitrary entries into GITHUB_PATH or GITHUB_OUTPUT.

Locations:

- `action.yml:130`
- `action.yml:136`
- `action.yml:137`
- `action.yml:138`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection

**Notes:**

Fixed three findings in hardened/action/action.yml:
1. Script injection (step 1, lines 37-38): Replaced `'${{ runner.os }}'` with `$env:RUNNER_OS` in the PowerShell run block. The shell is `pwsh`, so `$env:RUNNER_OS` is the correct environment variable reference.
2. Script injection (step 2, lines 148-149): Same fix applied to the second step's PowerShell run block.
3. GitHub env injection (lines 130, 136-138): Added PowerShell sanitization using `-replace '[\r\n]', ''` to strip newline characters from `$mingw_bin`, `$prefix`, `$gcc`, `$gxx`, and `$windres` before writing them to `$GITHUB_PATH` and `$GITHUB_OUTPUT`. Sanitized values are stored in `$safe_*` variables and used in the echo statements.

