# Open-Shepherd Wiki

Welcome to the Open-Shepherd documentation. Use the guides below to install, configure, and operate Open-Shepherd across VS Code-family IDEs, Neovim, and AI CLI agents.

## Table of Contents

- [1. What It Can Do & What It Monitors](#1-what-it-can-do--what-it-monitors)
- [2. What It Cannot Do & What It Is Not For](#2-what-it-cannot-do--what-it-is-not-for)
- [3. Architecture & Event Schema](#3-architecture--event-schema)
- [4. Setup Guides by IDE & AI Agent](#4-setup-guides-by-ide--ai-agent)
  - [4.1 VS Code, Cursor, Windsurf, VSCodium, Trae & Antigravity IDE](#41-vs-code-cursor-windsurf-vscodium-trae--antigravity-ide)
  - [4.2 Neovim (`>= 0.9`)](#42-neovim--09)
  - [4.3 Claude Code & AI CLI Agents](#43-claude-code--ai-cli-agents)
  - [4.4 Antigravity App (GUI), Antigravity CLI (`agy`) & Antigravity IDE](#44-antigravity-app-gui-antigravity-cli-agy--antigravity-ide)
- [5. Step-by-Step Operational Guides](#5-step-by-step-operational-guides)
  - [Guide 1: Choosing a Policy Mode (`strict` vs `balanced` vs `audit-only`)](#guide-1-choosing-a-policy-mode-strict-vs-balanced-vs-audit-only)
  - [Guide 2: Scanning Workspaces, MCP Servers & AI Agent Rules](#guide-2-scanning-workspaces-mcp-servers--ai-agent-rules)
  - [Guide 3: Managing Allow Lists, Trusted Publishers & Extension Integrity](#guide-3-managing-allow-lists-trusted-publishers--extension-integrity)
  - [Guide 4: Inspecting Live Logs & Streaming to a Webhook](#guide-4-inspecting-live-logs--streaming-to-a-webhook)
  - [Guide 5: Exporting Events to SIEM & Code Scanning (JSONL, CEF, OCSF, SARIF)](#guide-5-exporting-events-to-siem--code-scanning-jsonl-cef-ocsf-sarif)
  - [Guide 6: Troubleshooting & Handling False Positives](#guide-6-troubleshooting--handling-false-positives)
- [6. Reference: Commands, Settings & Environment Variables](#6-reference-commands-settings--environment-variables)

---

## 1. What It Can Do & What It Monitors

### VS Code Family (VS Code, Cursor, Windsurf, VSCodium, Antigravity, Trae)

- **Runtime API Monitoring (`src/monitor/`)**: Hooks `http`/`https`, `globalThis.fetch` (Undici), `net`/`tls` sockets, `dns`/`dns.promises`, `child_process`, `fs`/`fs/promises`, `worker_threads.Worker`, `vm`, `vscode.tasks`, and `vscode.workspace.fs` / `vscode.env.openExternal` / `vscode.env.clipboard.readText` inside the extension host.
- **Threat Detection, Blocking & Kill-Chain Correlation (`src/detection/`, `src/monitor/analysis/correlation-engine.ts`)**: Evaluates network requests, spawned processes, sensitive file reads/writes (such as `~/.ssh`, `~/.aws/credentials`, `.env`, and AI config files), and workspace tasks against security rules. `CorrelationEngine` also links sensitive local reads (credential files, clipboard, env secrets) to subsequent outbound network or process activity within a 60-second window.
- **Extension Static Scanner & Integrity Verification (`src/scanner/`, `src/lib/services/extension-integrity-service.ts`)**: Inspects installed extension metadata and JavaScript bundles for suspicious TTPs, and records SHA-256 digests (`package.json` + entrypoint) to detect silent on-disk tampering (`INTEGRITY_DRIFT`).
- **Workspace & AI Config Scanner (`src/scanner/workspace-security-scanner.ts`)**: Audits `.vscode/{settings,tasks,launch,mcp}.json`, `.git/{config,hooks/*}`, `.devcontainer/devcontainer.json`, `package.json`, `.npmrc`, `pip.conf`, MCP configs, hook configs, and AI agent rules/skills (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `.agents/rules/*`, `.agents/skills/*/SKILL.md`, `~/.gemini/antigravity-cli/settings.json`).
- **Allowlists, Trusted Publishers & Policy Modes**: Supports per-extension allowlists, trusted publishers, and three enforcement profiles (`strict`, `balanced`, `audit-only`).
- **Universal Event Output & SIEM Export**: Emits structured events to `~/.open-shepherd/events.jsonl` and optionally `OPEN_SHEPHERD_WEBHOOK`, and exports recorded `SecurityEvent`s to `jsonl`, `cef`, `ocsf` (v1.6.0), or `sarif` (2.1.0).

### Neovim (`>= 0.9`)

- **Terminal & Sensitive File Logging (`neovim-plugin/`)**: Logs `TermOpen` and `BufWritePost` events for `.env`, `.ssh`, and `id_rsa` paths to `~/.open-shepherd/events.jsonl`.

### AI CLI Agents (Claude Code, Antigravity CLI, etc.)

- **Lifecycle Enforcement & Audit Trail (`agent-hooks/shepherd-hook.mjs`)**: Evaluates `PreToolUse`, `PostToolUse`, `PreInvocation`, `SessionStart`, and `Stop` hook events. Blocks sensitive path access, dangerous shell commands, metadata/tunnel URLs, privileged `define_subagent` definitions, and `PreInvocation` prompt-injection directives by default (or logs audit-only when `OPEN_SHEPHERD_MODE=audit`).

---

## 2. What It Cannot Do & What It Is Not For

- **Not an OS-level EDR / Antivirus**: In VS Code, hooks only cover Node.js and VS Code APIs inside the extension host. Native binaries, external terminals, or processes outside the IDE are not monitored.
- **Neovim hook is audit-only; `shepherd-hook.mjs` enforces by default**: The Neovim plugin logs events for visibility, while `agent-hooks/shepherd-hook.mjs` actively blocks `PreToolUse` / `PreInvocation` violations in enforce mode (default) and logs audit-only when `OPEN_SHEPHERD_MODE=audit`.
- **Not a Sandbox or Firewall**: It complements—but does not replace—OS user permissions, containers, or network firewalls.
- **No Datadog Telemetry by Default**: Datadog Agent polling and OCSF submission are disabled unless `ide-shepherd.datadog.isEnabled` is explicitly set to `true`.

---

## 3. Architecture & Event Schema

Open-Shepherd keeps the upstream VS Code extension layout at the repository root (`src/`) so updates from `DataDog/IDE-SHEPHERD-extension` merge cleanly via [`.github/workflows/sync-upstream.yml`](../.github/workflows/sync-upstream.yml).

All adapters emit a unified JSONL event format to `~/.open-shepherd/events.jsonl` (overridable via `OPEN_SHEPHERD_LOG`) and optionally `POST` events to `OPEN_SHEPHERD_WEBHOOK`.

### Event Schema

```json
{
  "timestamp": "2026-11-17T13:00:00.000Z",
  "source": "vscode | neovim | agent-hook",
  "event_type": "terminal_open | sensitive_file_write | PreToolUse | ...",
  "severity": "info | warn | high | critical",
  "details": {}
}
```

---

## 4. Setup Guides by IDE & AI Agent

### 4.1 VS Code, Cursor, Windsurf, VSCodium, Trae & Antigravity IDE

1. **Install dependencies and compile:**

   ```bash
   npm ci
   npm run compile
   ```

2. **Choose how to run the extension:**
   - **Development mode:** Open the repository in your IDE and press `F5` to launch an Extension Development Host.
   - **Sideload as a `.vsix`:** Package and install locally:

     ```bash
     npx @vscode/vsce package
     code --install-extension open-shepherd-*.vsix
     ```

     _(Replace `code` with `cursor`, `windsurf`, `codium`, or your IDE's CLI binary if needed.)_

3. **Verify activation:**
   - Look for the **IDE Shepherd** shield icon in the Activity Bar.
   - Press `Ctrl+Shift+S` (`Cmd+Shift+S` on macOS) or run **IDE Shepherd: Show Security Status** from the Command Palette.

### 4.2 Neovim (`>= 0.9`)

1. **Add the plugin** to your plugin manager (for example, `lazy.nvim`):

   ```lua
   {
     dir = "/path/to/open-shepherd/neovim-plugin",
     config = function()
       require("open_shepherd").setup({
         -- Optional: override the default log path (~/.open-shepherd/events.jsonl)
         -- log_path = vim.fn.expand("~/.open-shepherd/events.jsonl"),
       })
     end,
   }
   ```

2. **Verify logging:** Restart Neovim, open a terminal buffer (`:terminal`), and confirm a `terminal_open` event was written to `~/.open-shepherd/events.jsonl`:

   ```bash
   tail -n 5 ~/.open-shepherd/events.jsonl
   ```

### 4.3 Claude Code & AI CLI Agents

1. **Register the hook** in `~/.claude/settings.json` (replacing `/path/to/open-shepherd` with your local clone path):

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "*",
           "hooks": [
             { "type": "command", "command": "node /path/to/open-shepherd/agent-hooks/shepherd-hook.mjs PreToolUse" }
           ]
         }
       ],
       "PostToolUse": [
         {
           "matcher": "*",
           "hooks": [
             { "type": "command", "command": "node /path/to/open-shepherd/agent-hooks/shepherd-hook.mjs PostToolUse" }
           ]
         }
       ]
     }
   }
   ```

2. **What `shepherd-hook.mjs` blocks by default (`PreToolUse` / `PreInvocation`):**
   - **Sensitive file reads/writes:** `.env` (excluding `.env.example`/`.sample`/`.template`), `~/.ssh/id_*`, `~/.aws/credentials`, `.azure`/`.kube`, `.git-credentials`, `.netrc`, `.npmrc`, `.pypirc`, `.claude/.credentials.json`, `.claude.json`, private keys/certs (`.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`), and Windows SAM/SYSTEM/SECURITY hives.
   - **Dangerous shell commands:** destructive `rm -rf` on `/` or `~`/`$HOME`, `curl|wget ... | sh|bash|zsh`, `nc -e`, encoded/bypass PowerShell flags, `Invoke-Expression`, `terraform destroy`, `diskpart.exe`, `Format-Volume`, `Clear-Disk`, and cloud metadata IP `169.254.169.254`.
   - **Suspicious or metadata URLs:** cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`) and common tunnel/exfiltration domains (`ngrok.io`, `webhook.site`, `oastify.com`, `interact.sh`, `burpcollaborator.*`, `trycloudflare.com`).
   - **Privileged subagents:** `define_subagent` calls with `enable_write_tools: true` or `enable_mcp_tools: true`.

3. **Smoke test the hook from your terminal:**

   ```bash
   echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}' \
     | node /path/to/open-shepherd/agent-hooks/shepherd-hook.mjs PreToolUse
   ```

   You should see a `deny` JSON response and a corresponding `high` severity entry appended to `~/.open-shepherd/events.jsonl`.

### 4.4 Antigravity App (GUI), Antigravity CLI (`agy`) & Antigravity IDE

1. **Copy the example hooks file** [`agent-hooks/antigravity-hooks.example.json`](../agent-hooks/antigravity-hooks.example.json) into one of:
   - **Global (Antigravity App, `agy` CLI, and Antigravity IDE):** `~/.gemini/config/hooks.json`
   - **Workspace-level:** `.agents/hooks.json`
2. **Update the paths** in the copied file so `/path/to/open-shepherd` points to your local clone.
3. **How enforcement works:**
   - `PreToolUse` returns `{"decision": "deny", "reason": "..."}` when a policy violation is detected (or `{"decision": "allow"}` otherwise).
   - `PreInvocation` checks `lastUserInput` for prompt-injection or remote shell directives and terminates the invocation (`terminationBehavior: "terminate"`) when `OPEN_SHEPHERD_MODE` is not `audit`.
   - `PostToolUse`, `SessionStart`, and `Stop` record lifecycle audit events to `~/.open-shepherd/events.jsonl`.
4. **IDE config auditing:** When running the Open-Shepherd extension inside Antigravity IDE, `WorkspaceSecurityScanner` also audits `.agents/hooks.json`, `.agents/mcp_config.json`, `.agents/rules/*`, `.agents/skills/*/SKILL.md`, `GEMINI.md`, and `~/.gemini/antigravity-cli/settings.json`.

---

## 5. Step-by-Step Operational Guides

### Guide 1: Choosing a Policy Mode (`strict` vs `balanced` vs `audit-only`)

Open-Shepherd separates **detection** from **blocking** using policy modes:

| Behavior                             | `strict`             | `balanced` (default)   | `audit-only`         |
| ------------------------------------ | -------------------- | ---------------------- | -------------------- |
| High/medium runtime rule violations  | Block + log          | Block (per rule) + log | Log only (no block)  |
| Inline `eval: true` `worker_threads` | Block + log          | Block + log            | Log only             |
| Non-eval `worker_threads.Worker`     | Block + log          | Allowed                | Allowed              |
| `vscode.env.clipboard.readText()`    | Block (returns `""`) | Correlated + allowed   | Correlated + allowed |

**To change the IDE policy mode:**

1. Open Settings (`Ctrl+,` / `Cmd+,`) and search for `ide-shepherd.policyMode`, **or** add it to your user `settings.json`:

   ```json
   { "ide-shepherd.policyMode": "balanced" }
   ```

2. Use `audit-only` while baselining a new workspace, `balanced` for everyday development, and `strict` in high-security environments.

**To change the AI CLI hook policy mode:**

- Default is `enforce` (blocks `PreToolUse` and `PreInvocation` violations).
- Set `OPEN_SHEPHERD_MODE=audit` in your shell or hook command to log violations without blocking:

  ```bash
  OPEN_SHEPHERD_MODE=audit node /path/to/open-shepherd/agent-hooks/shepherd-hook.mjs PreToolUse
  ```

### Guide 2: Scanning Workspaces, MCP Servers & AI Agent Rules

`WorkspaceSecurityScanner` inspects untrusted workspaces and global AI configs **before** tasks, MCP servers, or agent rules execute.

**When scans run:**

- Automatically at IDE startup (covering open workspaces and user-global MCP/AI configs).
- Automatically when workspace folders change or when you save a watched config file.
- Manually on demand via Command Palette → **IDE Shepherd: Scan Workspace & AI Configs** (`ide-shepherd.scanWorkspace`).

**What is scanned:**

| Category                | Files Checked                                                                                                                                                                                                                                                                                | What It Flags                                                            |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| VS Code & Devcontainers | `.vscode/settings.json`, `.vscode/tasks.json`, `.vscode/launch.json`, `.devcontainer/devcontainer.json`                                                                                                                                                                                      | Auto-run tasks (`folderOpen`), suspicious commands/hooks                 |
| Git & Package Managers  | `.git/config`, `.git/hooks/*` (non-`.sample`), `package.json`, `.npmrc`, `pip.conf`                                                                                                                                                                                                          | Active git hook scripts, lifecycle scripts, custom indexes               |
| MCP Server Configs      | `.vscode/mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.agents/mcp_config.json`, `~/.claude.json`, `~/.config/Claude/claude_desktop_config.json`, `~/.gemini/config/mcp_config.json`                                                                                                          | Untrusted/malicious MCP server commands and URLs                         |
| AI Rules, Skills & CLI  | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `.agents/rules/*`, `.agents/skills/*/SKILL.md`, `.agents/hooks.json`, `~/.gemini/config/hooks.json`, `~/.gemini/antigravity-cli/settings.json` | Prompt-injection patterns, hidden shell directives, unsafe hook commands |

> **Tip:** Workspaces marked as trusted via `TrustedWorkspaceService` are skipped during workspace scans; you can revoke workspace trust if you want a previously trusted repo re-scanned.

### Guide 3: Managing Allow Lists, Trusted Publishers & Extension Integrity

1. **Inspect extensions:** Open the **IDE Shepherd** sidebar and check **Extensions Analysis** (or press `Ctrl+Shift+E` / `Cmd+Shift+E` to run **IDE Shepherd: Scan Extensions**).
2. **Allowlist a specific extension:**
   - Open the **Allow Lists** view in the sidebar and click the **`+`** icon (**Add Extension to Allow List**), or run **IDE Shepherd: Add Extension to Allow List** from the Command Palette.
3. **Trust an entire publisher:**
   - Click the briefcase icon in **Allow Lists** (**Add Trusted Publisher**) or run **IDE Shepherd: Add Trusted Publisher**.
   - Default built-in trusted publishers are `ms-vscode`, `ms-python`, `github`, `git`, `datadog`, `cursor`, and `anysphere`.
4. **Automatic integrity drift protection (`ExtensionIntegrityService`):**
   - On startup, Open-Shepherd computes a SHA-256 digest of each user extension's `package.json` and `main` entrypoint.
   - If an extension's files change on disk without a version change, Open-Shepherd emits an `INTEGRITY_DRIFT` (`high`) security event and revokes its allowlist bypass until verified.

### Guide 4: Inspecting Live Logs & Streaming to a Webhook

Every adapter writes one JSON object per line to `~/.open-shepherd/events.jsonl` (or `$OPEN_SHEPHERD_LOG`).

**Useful `jq` commands:**

```bash
# Stream all events live
tail -f ~/.open-shepherd/events.jsonl | jq .

# Show only high or critical events
jq 'select(.severity == "high" or .severity == "critical")' ~/.open-shepherd/events.jsonl

# Show blocked AI agent hook decisions
jq 'select(.source == "agent-hook" and .details.decision == "deny")' ~/.open-shepherd/events.jsonl
```

**Streaming to a webhook:**

Set `OPEN_SHEPHERD_WEBHOOK` in the environment of your IDE or agent hook:

```bash
export OPEN_SHEPHERD_WEBHOOK="https://siem.example.com/ingest/open-shepherd"
```

- In `agent-hooks/shepherd-hook.mjs`, webhook delivery is triggered when a policy violation occurs and requires `https://` (or `http://` for `localhost` / `127.0.0.1` / `::1`).
- Local JSONL logging is always best-effort and never blocks your editor or agent if a write fails.

### Guide 5: Exporting Events to SIEM & Code Scanning (JSONL, CEF, OCSF, SARIF)

You can export the recorded VS Code `SecurityEvent`s from the current session at any time:

1. Open the **Security Events** view in the **IDE Shepherd** sidebar and click the export icon, **or** run **IDE Shepherd: Export Security Events (SIEM / SARIF)** (`ide-shepherd.exportEvents`) from the Command Palette.
2. Pick one of the four formats:
   - **`jsonl`** — Compact line-delimited JSON with `id`, `timestamp`, `severity`, `type`, `target`, `actor`, `rule`, `finding`, and `description`.
   - **`cef`** — ArcSight Common Event Format (`CEF:0|OpenShepherd|IDE-Shepherd|3.1.2|...`) for traditional SIEM collectors.
   - **`ocsf`** — Open Cybersecurity Schema Framework Detection Finding JSON lines (schema `1.6.0`).
   - **`sarif`** — SARIF `2.1.0` document compatible with GitHub Code Scanning and IDE SARIF viewers.
3. Choose the destination file in the save dialog.

### Guide 6: Troubleshooting & Handling False Positives

- **Check the logs:** Open the **Output** panel (`Ctrl+Shift+U` / `Cmd+Shift+U`) and select **Open Shepherd** from the channel dropdown.
- **Temporarily switch to audit mode:** Set `"ide-shepherd.policyMode": "audit-only"` in VS Code settings (or `OPEN_SHEPHERD_MODE=audit` for `shepherd-hook.mjs`) to observe events without blocking workflows.
- **Allowlist a legitimate extension or publisher:** Use **IDE Shepherd: Add Extension to Allow List** or **IDE Shepherd: Add Trusted Publisher**. If you need to reset your custom list, run **IDE Shepherd: Clear User Allow List**.
- **Reset noisy task history:** Run **IDE Shepherd: Clear Task Timeline** to clear the **Task Timeline** view.

---

## 6. Reference: Commands, Settings & Environment Variables

### VS Code Commands

| Command ID                                     | Title                                 | Default Shortcut               |
| ---------------------------------------------- | ------------------------------------- | ------------------------------ |
| `ide-shepherd.showStatus`                      | Show Security Status                  | `Ctrl+Shift+S` / `Cmd+Shift+S` |
| `ide-shepherd.scanExtensions`                  | Scan Extensions                       | `Ctrl+Shift+E` / `Cmd+Shift+E` |
| `ide-shepherd.scanWorkspace`                   | Scan Workspace & AI Configs           | —                              |
| `ide-shepherd.exportEvents`                    | Export Security Events (SIEM / SARIF) | —                              |
| `ide-shepherd.showEvents`                      | Show Security Events                  | —                              |
| `ide-shepherd.refreshStatus`                   | Refresh Status                        | —                              |
| `ide-shepherd.addToAllowList`                  | Add Extension to Allow List           | —                              |
| `ide-shepherd.removeFromAllowList`             | Remove Extension from Allow List      | —                              |
| `ide-shepherd.clearAllowList`                  | Clear User Allow List                 | —                              |
| `ide-shepherd.addTrustedPublisher`             | Add Trusted Publisher                 | —                              |
| `ide-shepherd.removeTrustedPublisher`          | Remove Trusted Publisher              | —                              |
| `ide-shepherd.settings.refresh`                | Refresh Settings                      | —                              |
| `ide-shepherd.settings.toggleDatadogTelemetry` | Toggle Datadog Telemetry              | —                              |
| `ide-shepherd.clearTaskTimeline`               | Clear Task Timeline                   | —                              |

### VS Code Settings

| Setting                          | Type      | Default      | Description                                                              |
| -------------------------------- | --------- | ------------ | ------------------------------------------------------------------------ |
| `ide-shepherd.isEnabled`         | `boolean` | `true`       | Enable IDE Shepherd security monitoring                                  |
| `ide-shepherd.policyMode`        | `string`  | `"balanced"` | Enforcement profile: `strict`, `balanced`, or `audit-only`               |
| `ide-shepherd.autoScan`          | `boolean` | `true`       | Automatically scan extensions on startup                                 |
| `ide-shepherd.notificationLevel` | `string`  | `"high"`     | Minimum severity for notifications: `all`, `high`, `critical`, or `none` |
| `ide-shepherd.maxEvents`         | `number`  | `100`        | Maximum security events retained in memory (`10`–`1000`)                 |
| `ide-shepherd.showStatusBar`     | `boolean` | `true`       | Show IDE Shepherd status in the status bar                               |
| `ide-shepherd.datadog.isEnabled` | `boolean` | `false`      | Enable Datadog telemetry integration (requires local Datadog Agent)      |
| `ide-shepherd.datadog.agentPort` | `number`  | `10518`      | Local Datadog Agent TCP port for log forwarding (`1024`–`65535`)         |

### Environment Variables

| Variable                | Default                         | Applies To             | Description                                                                      |
| ----------------------- | ------------------------------- | ---------------------- | -------------------------------------------------------------------------------- |
| `OPEN_SHEPHERD_LOG`     | `~/.open-shepherd/events.jsonl` | VS Code, Neovim, Hooks | Path to local JSONL event log                                                    |
| `OPEN_SHEPHERD_WEBHOOK` | _(unset)_                       | VS Code, Agent Hooks   | Optional HTTP(S) endpoint for `POST` JSON events                                 |
| `OPEN_SHEPHERD_MODE`    | `enforce`                       | Agent Hooks            | Set to `audit` to log `PreToolUse` / `PreInvocation` violations without blocking |
