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

- **Runtime API Monitoring** (`src/monitor/`): Hooks `http`/`https`, global `fetch`, `net`/`tls` sockets (`connect`, `createConnection`, `Socket.prototype.connect`), `dns` (`lookup`, `resolve*`, `dns.promises`), `child_process` (with `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/`NODE_OPTIONS` injection checks), `fs`/`fs/promises`, `worker_threads` (`Worker`), `vm` (`runInNewContext`/`runInContext`/`compileFunction`/`Script`), `vscode.tasks`, `vscode.workspace.fs` (`readFile`/`writeFile`), and `vscode.env` (`openExternal`, `clipboard.readText`).
- **Threat Detection, Kill-Chain Correlation & Blocking** (`src/detection/`, `src/monitor/analysis/correlation-engine.ts`): Evaluates network requests (including cloud metadata SSRF, IPv4-mapped IPv6, DNS tunneling entropy/labels, and non-standard ports), spawned processes, 70+ cross-platform sensitive file/credential paths (`.env`, SSH, AWS, Azure, GCP, Kubernetes, Docker, Claude, Windows SAM/NTDS/Vault, browser profiles), and multi-step kill-chain correlation (sensitive FS/clipboard read followed by outbound network or process execution within 60s).
- **Pre-Execution Workspace & AI Config Scanner** (`src/scanner/workspace-security-scanner.ts`, `src/detection/workspace-rules.ts`): Audits `.vscode/settings.json`, `.vscode/tasks.json` (`runOn: "folderOpen"`, OS-specific task blocks), `.vscode/launch.json`, `.git/config` (`fsmonitor`, `sshCommand`, `hooksPath`, `credential.helper`), active `.git/hooks/*`, `.devcontainer/devcontainer.json`, `package.json` install scripts, `.npmrc`/`pip.conf`, MCP configs (`.vscode/mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.agents/mcp_config.json`, `~/.gemini/config/mcp_config.json`, `~/.claude.json`), AI instruction/skill files (`.cursorrules`, `.cursor/rules/*`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.agents/rules/*`, `.agents/agents/*`, `.agents/skills/*/SKILL.md`, `.github/copilot-instructions.md`, `.windsurfrules`, `.clinerules`) for hidden Unicode/bidi/HTML-comment prompt injection, Antigravity lifecycle hooks (`.agents/hooks.json`, `~/.gemini/config/hooks.json`), Antigravity CLI permissions (`~/.gemini/antigravity-cli/settings.json`), and recent Antigravity conversation transcripts (`transcript.jsonl`).
- **Extension Integrity & Allowlists** (`src/lib/services/extension-integrity-service.ts`, `src/lib/services/allowlist-service.ts`): Computes SHA-256 baselines for installed extensions (`package.json` + entrypoint), alerts on silent mid-version drift, and supports session-only (`Allow once (session)`), TTL-bound, and integrity-pinned allowlist entries.
- **Policy Modes & SIEM Export** (`src/lib/services/policy-service.ts`, `src/lib/services/siem-exporter.ts`): Supports `audit`, `balanced` (default), and `strict` policy modes (`ide-shepherd.policyMode`), plus one-click export (`ide-shepherd.exportEvents`) in `jsonl`, `cef`, `ocsf`, and `sarif` formats alongside `~/.open-shepherd/events.jsonl` and `OPEN_SHEPHERD_WEBHOOK`.

### Neovim (`>= 0.9`)

- **Terminal & Sensitive File Logging (`neovim-plugin/`)**: Logs `TermOpen` and `BufWritePost` events for `.env`, `.ssh`, and `id_rsa` paths to `~/.open-shepherd/events.jsonl`.

### AI CLI & GUI Agents (Claude Code, Google Antigravity App / CLI / IDE)

- **Lifecycle Hook Policy Enforcement & Audit Trail** (`agent-hooks/shepherd-hook.mjs`): Evaluates and logs hook events (`PreToolUse`, `PreInvocation`, `PostToolUse`, `SessionStart`, `Stop`) across Claude Code and Google Antigravity App / `agy` CLI / IDE, blocking dangerous shell commands, sensitive file access, metadata/exfiltration URLs, privileged subagents, and prompt injection directives in enforce mode (default) while logging to `~/.open-shepherd/events.jsonl` and optional webhook.
- **Level 4 Network Proxy Guard** (`agent-hooks/antigravity-proxy-guard.mjs`): Lightweight zero-dependency local HTTP/CONNECT proxy that audits and blocks cloud metadata SSRF (`169.254.169.254`, `169.254.170.2`, `100.100.100.200`, `metadata.google.internal`, `fd00:ec2::254`) and exfiltration/tunnel domains (`ngrok.io`, `webhook.site`, `oastify.com`, `interact.sh`, `burpcollaborator.me`, `burpcollaborator.net`, `trycloudflare.com`) for `agy` CLI, GUI, and local MCP child processes running outside the Extension Host.

---

## 2. What It Cannot Do & What It Is Not For

- **Not an OS-level EDR / Antivirus**: In VS Code, hooks only cover Node.js APIs inside the extension host. Native binaries, external terminals, or processes outside the IDE are not monitored unless routed through `shepherd-hook.mjs` or `antigravity-proxy-guard.mjs`.
- **Neovim hook is audit-only; `shepherd-hook.mjs` and `antigravity-proxy-guard.mjs` enforce by default**: The Neovim plugin logs events for visibility, while `agent-hooks/shepherd-hook.mjs` and `agent-hooks/antigravity-proxy-guard.mjs` actively block violations in enforce mode (default) and log audit-only when `OPEN_SHEPHERD_MODE=audit`.
- **Not a Sandbox or Firewall**: It complements—but does not replace—OS user permissions, containers, or network firewalls.
- **No Datadog Telemetry by Default**: Datadog Agent polling and OCSF submission are disabled unless `ide-shepherd.datadog.isEnabled` is explicitly set to `true`.

---

## 3. Architecture & Event Schema

All adapters emit a unified JSONL event format to `~/.open-shepherd/events.jsonl` (overridable via `OPEN_SHEPHERD_LOG`) and optionally POST events to `OPEN_SHEPHERD_WEBHOOK`.

### Event Schema

```json
{
  "timestamp": "2026-11-17T13:00:00.000Z",
  "source": "vscode | neovim | agent-hook | proxy-guard",
  "event_type": "terminal_open | sensitive_file_write | PreToolUse | network_egress | ...",
  "severity": "info | warn | high | critical",
  "details": {}
}
```

---

## 4. Setup by IDE / Agent

---

## 5. Step-by-Step Operational Guides

Package or sideload the extension as a `.vsix` (`engines.vscode: "^1.85.0"`), or run it in Extension Development Host (`F5`).

### Commands & Settings

- `ide-shepherd.scanWorkspace` (**IDE Shepherd: Scan Workspace & AI Configs for Security Risks**): Manually trigger a full workspace, global MCP, and Antigravity config/transcript security scan.
- `ide-shepherd.exportEvents` (**IDE Shepherd: Export Security Events (JSONL / CEF / OCSF / SARIF)**): Export captured security events in `jsonl`, `cef`, `ocsf`, or `sarif` format.
- `ide-shepherd.policyMode`: Choose `audit` (log only), `balanced` (block high-severity threats, default), or `strict` (block medium and high-severity threats).

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

1. Copy [`agent-hooks/antigravity-hooks.example.json`](../agent-hooks/antigravity-hooks.example.json) into `~/.gemini/config/hooks.json` (global across Antigravity App, `agy` CLI, and Antigravity IDE) or `.agents/hooks.json` (workspace-level), updating `/path/to/open-shepherd` to your local clone path.
2. When running the Open-Shepherd extension inside Antigravity IDE, `WorkspaceSecurityScanner` also audits `.agents/hooks.json`, `.agents/mcp_config.json`, `.agents/rules/*`, `.agents/skills/*/SKILL.md`, `GEMINI.md`, and `~/.gemini/antigravity-cli/settings.json`.
3. `WorkspaceSecurityScanner` also audits global Antigravity skills (`~/.gemini/config/skills/*/SKILL.md`, `~/.gemini/skills/*/SKILL.md`, `~/.gemini/antigravity-cli/skills/*/SKILL.md`), plugins (`~/.gemini/config/plugins/*/{hooks,mcp_config}.json`), and conversation transcripts (`~/.gemini/antigravity*/brain/*/.system_generated/logs/transcript.jsonl`) for `--dangerously-skip-permissions` or unhooked dangerous commands.
4. For Level 4 network protection of `agy` CLI, GUI, and local MCP child processes running outside the Extension Host, start [`agent-hooks/antigravity-proxy-guard.mjs`](../agent-hooks/antigravity-proxy-guard.mjs) (`node agent-hooks/antigravity-proxy-guard.mjs`) and launch processes with `HTTP_PROXY=http://127.0.0.1:8787 HTTPS_PROXY=http://127.0.0.1:8787` to audit and block cloud metadata SSRF and exfiltration domains.

You can export the recorded VS Code `SecurityEvent`s from the current session at any time:

1. Open the **Security Events** view in the **IDE Shepherd** sidebar and click the export icon, **or** run **IDE Shepherd: Export Security Events (SIEM / SARIF)** (`ide-shepherd.exportEvents`) from the Command Palette.
2. Pick one of the four formats:
   - **`jsonl`** — Compact line-delimited JSON with `id`, `timestamp`, `severity`, `type`, `target`, `actor`, `rule`, `finding`, and `description`.
   - **`cef`** — ArcSight Common Event Format (`CEF:0|OpenShepherd|IDE-Shepherd|3.1.2|...`) for traditional SIEM collectors.
   - **`ocsf`** — Open Cybersecurity Schema Framework Detection Finding JSON lines (schema `1.6.0`).
   - **`sarif`** — SARIF `2.1.0` document compatible with GitHub Code Scanning and IDE SARIF viewers.
3. Choose the destination file in the save dialog.

### Guide 6: Troubleshooting & Handling False Positives

## 5. Environment Variables

| Variable                   | Default                         | Description                                                  |
| -------------------------- | ------------------------------- | ------------------------------------------------------------ |
| `OPEN_SHEPHERD_LOG`        | `~/.open-shepherd/events.jsonl` | Path to local JSONL event log                                |
| `OPEN_SHEPHERD_WEBHOOK`    | _(unset)_                       | Optional HTTP(S) endpoint for `POST` JSON events             |
| `OPEN_SHEPHERD_MODE`       | `enforce`                       | Hook/proxy policy mode (`enforce` blocks, `audit` logs)      |
| `OPEN_SHEPHERD_PROXY_PORT` | `8787`                          | Listening port for `agent-hooks/antigravity-proxy-guard.mjs` |
| `OPEN_SHEPHERD_PROXY_HOST` | `127.0.0.1`                     | Bind address for `agent-hooks/antigravity-proxy-guard.mjs`   |
