# Changelog

## [1.0.0] - 2026-11-25

Initial public release.

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
