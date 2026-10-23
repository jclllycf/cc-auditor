# CC Auditor · Windows pre-use environment checks

[简体中文](README.md) · [Windows installation, Chinese](INSTALL_WINDOWS_ZH.md) · [Skill / MCP configuration](MCP_CONFIGURATION_ZH.md) · [Privacy](PRIVACY_ZH.md)

CC Auditor helps Windows users inspect their environment **before installing or using Claude**. It runs locally, asks for native user consent, checks relevant system, browser and proxy evidence, and produces Chinese PDF reports. Claude, Python, SDKs and a Claude account are not required.

**Status: v3.6 release candidate.** Available downloads and completed validation are defined by the actual GitHub Release and its acceptance receipt. A candidate is not a stable release. This is an independent project, not an Anthropic product.

## Install and run

1. Download the Windows x64 portable ZIP and `SHA256SUMS.txt` from this repository's **Releases** page. GitHub's automatic “Source code” archive is not a runnable Windows package.
2. Calculate the ZIP's SHA-256 in PowerShell and compare it with the matching filename in `SHA256SUMS.txt`:

   ```powershell
   Get-FileHash -LiteralPath '.\CC_Auditor_<version>_Windows_x64.zip' -Algorithm SHA256
   ```

3. Extract the entire archive to a user-writable folder, for example `C:\Tools\CC-Auditor`. Keep the EXE and `_internal` files together. A compatible Microsoft Visual C++ x64 v14 runtime (14.44 or newer recommended) is required. If absent, install it yourself from [Microsoft](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist). The package does not redistribute Microsoft runtime DLLs or install them automatically.
4. For Web checks, open your everyday Chrome, Edge or Firefox profile in a normal window. Do not open Claude for the test.
5. Run `CC_Auditor\启动预检.cmd` or double-click `CC_Auditor.exe`. Select permitted scopes and confirm the native consent form yourself.
6. Open the returned local PDF paths. Evidence and reports are saved under `data\preflight_v3\<run-id>\` beside the EXE. Two PDFs are always produced after a completed run; an evidence checklist is added when actionable gaps remain.

No AI Agent is needed for standalone use. Windows 11 x64 is the primary validation target; see the [support matrix](SUPPORT_MATRIX_ZH.md) for qualified compatibility claims. Do not disable security software or bypass an organizational trust policy to run it.

## Optional local Agent integration

Install the supplied `skills/cc-auditor-preflight` folder in your Agent's supported skills directory. Configure its **local stdio** MCP server to execute:

```text
C:\Tools\CC-Auditor\CC_Auditor\CC_Auditor.exe --mcp
```

Codex and Gemini CLI examples are in [MCP_CONFIGURATION_ZH.md](MCP_CONFIGURATION_ZH.md) and the Skill's `references/CONFIGURATION.md`. Call `audit_capabilities` first. Scans use `prepare_deep_preflight`, followed by `run_approved_deep_preflight` with the returned `scan_id`. Only the person using the Windows computer may approve the consent form; no PIN, boolean parameter or Skill installation substitutes for approval.

A cloud Agent cannot access your PC merely by loading this Skill. Use a local, non-Claude Agent. Its own provider communication is separate from the scanner's networking boundaries.

## Understand the result

Desktop, Web, CLI and API receive separate **positive environment health scores**: higher is better. The score is an engineering assessment, not a ban probability or a promise of service, signup or payment success. Missing Claude installations, accounts and optional location declarations do not lower the technical score. Remote API execution cannot be scored using the local PC's network path.

The scanner does not actively contact or resolve Claude / Anthropic destinations in this preflight. User-approved neutral receivers can observe IP, DNS and protocol metadata. Reports remain local unless you choose to share them; summaries sent through an Agent may reach its model provider. Public feedback must be redacted.

Close the program, remove its MCP entry and installed Skill if used, then delete only its portable folder and results you no longer need. No system-wide font installation or persistent scanner service is required.

Original code is licensed under MIT, Copyright (c) 2026 jclllycf; see `LICENSE`. Third-party components retain their own licenses and accompanying notices.
