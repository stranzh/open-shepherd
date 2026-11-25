# Changelog

## [3.2.0] - 2026-11-25

### Headless CLI & Pre-Clone Scanning

- **`open-shepherd` CLI** — new `bin` entry (`./out/cli/index.js`) exposing `scan`, `scan-repo`, and `policy` commands that run without VS Code; `--format jsonl|sarif|ocsf|cef`, `--global` for user-level AI/IDE configs, `--inventory` for OCSF inventory, and `--syslog udp|tcp|tls://host:port` forwarding; exit codes `0` (no HIGH findings), `1` (HIGH findings), `2` (usage/IO failure)
- **`scan-repo`** — scans a remote GitHub repository through the GitHub API (`--ref`, `--token`, or `GITHUB_TOKEN`/`GH_TOKEN`) without cloning
- **`scan --inventory`** — emits OCSF Inventory Info (`class_uid: 5001`) for installed IDEs and extensions

### Enterprise Policy & Integrations

- **`policy audit|impact|generate`** — audit enterprise VS Code/IDE policies, evaluate allowlist impact on installed extensions, and compile GitOps allow/deny lists into VS Code and ADMX policy manifests (see `docs/policy-gitops/`)
- **Syslog transport** — RFC 5424 over UDP, TCP, or TLS for `scan` and `scan-repo`
- **Age-hold advisories** — extensions published or updated in the last 48 hours raise an advisory finding; warns when `extensions.autoUpdate` can bypass the review window
- **Revocation feeds** — installed extensions are checked against the VS Marketplace `RemovedPackages.md` and Open VSX revoked feed (24 h cache)
- **H207 correlation** — `H207 Multi-Store AI/IDE Session Theft` fires when one extension reads multiple AI/IDE token-store families inside the correlation window
- **Tunnel detection** — `ide_devtunnel_endpoint` (Dev Tunnels / `devtunnels.ms` traffic) and `ide_remote_tunnel_execution` (`code tunnel service install` / `internal-run` LOLRMM)

### Detection

- **IDE fork registry** — centralized registry covering VS Code, VSCodium, Cursor, Windsurf, Antigravity, Claude Code, Codex, OpenCode, Copilot CLI, Zed, Devin, Kiro, Trae, and Qoder, including workspace and home config paths
- **AI & MCP config rules** — `ai_api_base_url_override` (CVE-2026-21852 custom API base URL), `mcp_unpinned_or_shell_server`, `mcp_remote_endpoint`, `mcp_stdio_script_drift`, `claude_enable_all_project_mcp`, `ai_chat_tools_auto_approve`, `ai_chat_permissive_default`, `cursor_cli_dangerous_config`, `zed_vulnerable_idesaster_version`
- **Editor config rules** — `vim_exrc_enabled`, `vim_local_rc_present`, `vim_local_rc_execution`, `nvim_lazy_lock_unpinned`, `emacs_dir_locals_exec`
- **Build & notebook rules** — `jupyter_hidden_cell_exec`, `jupyter_shell_magic_exec`, `jupyter_unsafe_deserialization`, `msbuild_inline_code_task`, `msbuild_suspicious_exec_task`, `xcode_build_phase_suspicious_script`
- **Repo hook rules** — `pre_commit_unpinned_rev`, `pre_commit_untrusted_repo_url`, `pre_commit_suspicious_local_entry`, `husky_suspicious_hook`
- **Token-store and GlassWorm coverage** — filesystem rules for AI/IDE credential stores plus `GlassWorm` invisible-Unicode `eval` detection

### Packaging

- **npm CLI packaging** — added a `prepublishOnly` compile step and `.npmignore` so `npm pack` ships `out/` (including `out/cli/index.js`) without `out/test/**`, `src/`, or dev tooling
- **VSIX hygiene** — `.vscodeignore` now excludes `graphify-out/**` and `.agents/**` so local agent/graph artifacts never enter the `.vsix`

### Documentation

- **Setup guides** — `docs/WIKI.md` sections for the VS Code family, Neovim, Claude Code/AI CLI agents, and the Antigravity app/CLI, plus step-by-step operational guides
- **CI & hooks guide** — `docs/ci-and-hooks.md` with pre-commit, pre-commit-framework, CI, and pre-clone recipes
- **Detection content** — Sigma and osquery examples under `docs/detections/`

---

## [3.1.2] - 2026-06-09

### Detection — Miasma Supply-Chain Worm (June 2026)

Three new rules targeting the TTPs newly observed in the Miasma worm campaign (TeamPCP, June 5 2026), which compromised 73 Microsoft repositories by planting IDE/AI-agent config files that auto-execute a credential-harvesting payload on folder open or agent session start.

- **`task_node_hidden_dir_script`** (High) — task rule: matches `node .github/setup.js` — the Miasma worm execution command fired via a `folderOpen` task
- **`write_ai_agent_config_miasma_setupjs`** (High) — FS write rule: fires when **both** (1) the destination is `.claude/settings.json`, `.gemini/settings.json`, or `.cursor/rules/*.mdc` **and** (2) the written content contains `node .github/setup.js`; targets the SessionStart hook and `alwaysApply` prompt-injection persistence mechanism; the dual-signal requirement prevents false positives from legitimate AI coding-agent config management
- **`malware_download_domains`** — extended with Miasma C2 domains: `git-service.com` (May 2026 PyPI wave) and `m-kosche.com` (June 2026 Azure wave)

### Infrastructure

- **Content-pattern scanning for FS write rules** — `FsRule` now accepts an optional `contentPattern?: RegExp`; when set, `FsAnalyzer` gates rule firing on both the normalized file path and the written payload. Write data (string or `Buffer`) is decoded up to 64 KB before matching; content is intentionally excluded from `FsEvent.toJSON()` so it is never emitted in telemetry or logs. All six `fs` write/append call sites (`writeFile`, `appendFile`, and their sync and promise variants) extract and forward the write payload to the analyzer.

---

## [3.1.1] - 2026-05-26

### Features

- **`vscode.tasks.executeTask` instrumentation** — patches `executeTask` on the shared `vscode` module object so extension-initiated tasks are blocked before VS Code queues them, closing the gap left by `onDidStartTask` which fires only after execution begins
- **What's New page** — opens on first install and on each version update, pulling release notes from the bundled `CHANGELOG.md`; shown at most once per version per installation via a versioned marker file in the extension directory

### Detection

- **`task_npx_auto_approve_remote`** (High) — `npx` with `-y`/`--yes` and a `github:` package specifier
- **`stealth_task_remote_install`** (High) — hidden task (`presentationOptions.focus = false`) combined with auto-confirmed remote npx install; requires both signals to fire

### Bug Fixes

- **Oversized bundle tail scan** — files between 1 MB and 25 MB now have their last 100 KB scanned; the previous 1 MB hard cap silently skipped these files entirely
- **Source rule false positives** — `download_and_execute` now requires a temp-directory reference as a third signal; `reverse_shell` now requires a shell binary literal (`/bin/sh`, `cmd.exe`, etc.) rather than any exec/spawn call
- **What's New page not shown after Cursor auto-update** — Cursor updates extensions in-place, preserving existing files in the extension directory. The previous marker-based check (file presence only) meant the page was silently skipped after every Cursor update. The marker file now stores the version string; the page shows whenever the stored version differs from the current one.
- **Telemetry disabled and agent "Pending Restart" after update**

---

## [3.1.0] - 2026-05-26

### Features

- **`vscode.tasks.executeTask` instrumentation** — patches `executeTask` on the shared `vscode` module object so extension-initiated tasks are blocked before VS Code queues them, closing the gap left by `onDidStartTask` which fires only after execution begins
- **What's New page** — opens on first install and on each version update, pulling release notes from the bundled `CHANGELOG.md`; shown at most once per install via a marker file in the extension directory

### Detection

- **`task_npx_auto_approve_remote`** (High) — `npx` with `-y`/`--yes` and a `github:` package specifier
- **`stealth_task_remote_install`** (High) — hidden task (`presentationOptions.focus = false`) combined with auto-confirmed remote npx install; requires both signals to fire

### Bug Fixes

- **Oversized bundle tail scan** — files between 1 MB and 25 MB now have their last 100 KB scanned; the previous 1 MB hard cap silently skipped these files entirely
- **Source rule false positives** — `download_and_execute` now requires a temp-directory reference as a third signal; `reverse_shell` now requires a shell binary literal (`/bin/sh`, `cmd.exe`, etc.) rather than any exec/spawn call

---

## [3.0.0] - 2026-05-07

### Feature Release

- **File system monitoring** — Patches `fs.readFile`, `fs.writeFile`, `fs.appendFile` (sync, callback, and promise variants) to detect and block access to sensitive files. Adds 15 detection rules across read/write targets covering SSH keys, cloud credentials, shell history, persistence locations (cron, launchd, authorized_keys, hosts file, shell profiles), with cross-platform Windows path support

### New Features

- **Static source analysis (beta)** — IDE Shepherd now scans every `.js` file inside an extension's directory (including `node_modules`) for known attack primitives at the TTP level. Four rules are included in the initial release:
  - `download_and_execute` (Medium) — detects co-occurrence of HTTP fetch primitives and process execution calls
  - `reverse_shell` (High) — detects TCP socket creation combined with process execution, a signature of reverse shell setup
  - `eval_dynamic_payload` (High) — detects `eval` or `new Function` applied to a base64/encoded payload
  - `detached_unref_pattern` (Medium) — detects `detached: true` with `.unref()` used to launch a persistent background process

- **Retroactive module patching** — the module loader hook is now installed as the very first operation during extension activation, before any service initialization, minimizing the window in which another extension's early `require()` can bypass instrumentation. Cached modules are also patched in-place at startup.

- **New process monitoring rules** — two additional rules added to the child process interceptor:
  - `windows_script_host` (High) — flags execution via `cscript`, `wscript`, or `mshta`, which are never used by legitimate VS Code extensions
  - `detached_silent_process` (High) — flags processes spawned with `detached: true` and `stdio: 'ignore'`, a common payload-delivery pattern

## [2.1.0] - 2026-04-14

### Bug Fixes

- **Telemetry stability** — agent monitor now requires 3 consecutive failed health checks (~90s) before disabling telemetry, preventing false positives during IDE restarts or Cursor updates
- **Deadlock prevention** — replaced busy-wait spin-lock in `IDEStatusService` with a proper FIFO async mutex
- **Queue data loss** — fixed race condition in `OCSFTracker.flushQueuedEvents()` where events arriving during a flush could be silently dropped
- **Interval leak** — added `deactivate()` hook to stop the auto-refresh interval on extension teardown
- **Task rule misses** — normalize shell line-continuations and newlines in task commands before pattern matching
- **Risk score inflation** — scoring model now uses weighted-max with diminishing returns; multiple low-severity patterns no longer incorrectly escalate to high risk
