# Open-Shepherd Wiki

## 1. What It Can Do & What It Monitors

### VS Code Family (VS Code, Cursor, Windsurf, VSCodium, Antigravity, Trae)

- **Runtime API Monitoring** (`src/monitor/`): Hooks `http`/`https`, global `fetch`, `net`/`tls` sockets (`connect`, `createConnection`, `Socket.prototype.connect`), `dns` (`lookup`, `resolve*`, `dns.promises`), `child_process` (with `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/`NODE_OPTIONS` injection checks), `fs`/`fs/promises`, `worker_threads` (`Worker`), `vm` (`runInNewContext`/`runInContext`/`compileFunction`/`Script`), `vscode.tasks`, `vscode.workspace.fs` (`readFile`/`writeFile`), and `vscode.env` (`openExternal`, `clipboard.readText`).
- **Threat Detection, Kill-Chain Correlation & Blocking** (`src/detection/`, `src/monitor/analysis/correlation-engine.ts`): Evaluates network requests (including cloud metadata SSRF, IPv4-mapped IPv6, DNS tunneling entropy/labels, and non-standard ports), spawned processes, 70+ cross-platform sensitive file/credential paths (`.env`, SSH, AWS, Azure, GCP, Kubernetes, Docker, Claude, Windows SAM/NTDS/Vault, browser profiles), and multi-step kill-chain correlation (sensitive FS/clipboard read followed by outbound network or process execution within 60s).
- **Pre-Execution Workspace & AI Config Scanner** (`src/scanner/workspace-security-scanner.ts`, `src/detection/workspace-rules.ts`): Audits `.vscode/settings.json`, `.vscode/tasks.json` (`runOn: "folderOpen"`, OS-specific task blocks), `.vscode/launch.json`, `.git/config` (`fsmonitor`, `sshCommand`, `hooksPath`, `credential.helper`), active `.git/hooks/*`, `.devcontainer/devcontainer.json`, `package.json` install scripts, `.npmrc`/`pip.conf`, MCP configs (`.vscode/mcp.json`, `.mcp.json`, `.cursor/mcp.json`, `.agents/mcp_config.json`, `~/.gemini/config/mcp_config.json`, `~/.claude.json`), AI instruction/skill files (`.cursorrules`, `.cursor/rules/*`, `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.agents/rules/*`, `.agents/agents/*`, `.agents/skills/*/SKILL.md`, `.github/copilot-instructions.md`, `.windsurfrules`, `.clinerules`) for hidden Unicode/bidi/HTML-comment prompt injection, Antigravity lifecycle hooks (`.agents/hooks.json`, `~/.gemini/config/hooks.json`), Antigravity CLI permissions (`~/.gemini/antigravity-cli/settings.json`), and recent Antigravity conversation transcripts (`transcript.jsonl`).
- **Extension Integrity & Allowlists** (`src/lib/services/extension-integrity-service.ts`, `src/lib/services/allowlist-service.ts`): Computes SHA-256 baselines for installed extensions (`package.json` + entrypoint), alerts on silent mid-version drift, and supports session-only (`Allow once (session)`), TTL-bound, and integrity-pinned allowlist entries.
- **Policy Modes & SIEM Export** (`src/lib/services/policy-service.ts`, `src/lib/services/siem-exporter.ts`): Supports `audit`, `balanced` (default), and `strict` policy modes (`ide-shepherd.policyMode`), plus one-click export (`ide-shepherd.exportEvents`) in `jsonl`, `cef`, `ocsf`, and `sarif` formats alongside `~/.open-shepherd/events.jsonl` and `OPEN_SHEPHERD_WEBHOOK`.

### Neovim (`>= 0.9`)

- **Terminal & Sensitive File Logging** (`neovim-plugin/`): Logs `TermOpen` and `BufWritePost` events for `.env`, `.ssh`, and `id_rsa` paths to `~/.open-shepherd/events.jsonl`.

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

## 3. Architecture

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

### VS Code, Cursor, Windsurf, VSCodium, Antigravity

```bash
npm install
npm run compile
```

Package or sideload the extension as a `.vsix` (`engines.vscode: "^1.85.0"`), or run it in Extension Development Host (`F5`).

### Commands & Settings

- `ide-shepherd.scanWorkspace` (**IDE Shepherd: Scan Workspace & AI Configs for Security Risks**): Manually trigger a full workspace, global MCP, and Antigravity config/transcript security scan.
- `ide-shepherd.exportEvents` (**IDE Shepherd: Export Security Events (JSONL / CEF / OCSF / SARIF)**): Export captured security events in `jsonl`, `cef`, `ocsf`, or `sarif` format.
- `ide-shepherd.policyMode`: Choose `audit` (log only), `balanced` (block high-severity threats, default), or `strict` (block medium and high-severity threats).

### Neovim (`>= 0.9`)

Add `neovim-plugin/` to your plugin manager (e.g. `lazy.nvim`):

```lua
{
  dir = "/path/to/open-shepherd/neovim-plugin",
  config = function()
    require("open_shepherd").setup()
  end,
}
```

### Claude Code / AI CLI Agents

Add to `~/.claude/settings.json`:

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
    ]
  }
}
```

### Antigravity App (GUI), Antigravity CLI (agy), and Antigravity IDE

1. Copy [`agent-hooks/antigravity-hooks.example.json`](../agent-hooks/antigravity-hooks.example.json) into `~/.gemini/config/hooks.json` (global across Antigravity App, `agy` CLI, and Antigravity IDE) or `.agents/hooks.json` (workspace-level), updating `/path/to/open-shepherd` to your local clone path.
2. When running the Open-Shepherd extension inside Antigravity IDE, `WorkspaceSecurityScanner` also audits `.agents/hooks.json`, `.agents/mcp_config.json`, `.agents/rules/*`, `.agents/skills/*/SKILL.md`, `GEMINI.md`, and `~/.gemini/antigravity-cli/settings.json`.
3. `WorkspaceSecurityScanner` also audits global Antigravity skills (`~/.gemini/config/skills/*/SKILL.md`, `~/.gemini/skills/*/SKILL.md`, `~/.gemini/antigravity-cli/skills/*/SKILL.md`), plugins (`~/.gemini/config/plugins/*/{hooks,mcp_config}.json`), and conversation transcripts (`~/.gemini/antigravity*/brain/*/.system_generated/logs/transcript.jsonl`) for `--dangerously-skip-permissions` or unhooked dangerous commands.
4. For Level 4 network protection of `agy` CLI, GUI, and local MCP child processes running outside the Extension Host, start [`agent-hooks/antigravity-proxy-guard.mjs`](../agent-hooks/antigravity-proxy-guard.mjs) (`node agent-hooks/antigravity-proxy-guard.mjs`) and launch processes with `HTTP_PROXY=http://127.0.0.1:8787 HTTPS_PROXY=http://127.0.0.1:8787` to audit and block cloud metadata SSRF and exfiltration domains.

---

## 5. Environment Variables

| Variable                   | Default                         | Description                                                  |
| -------------------------- | ------------------------------- | ------------------------------------------------------------ |
| `OPEN_SHEPHERD_LOG`        | `~/.open-shepherd/events.jsonl` | Path to local JSONL event log                                |
| `OPEN_SHEPHERD_WEBHOOK`    | _(unset)_                       | Optional HTTP(S) endpoint for `POST` JSON events             |
| `OPEN_SHEPHERD_MODE`       | `enforce`                       | Hook/proxy policy mode (`enforce` blocks, `audit` logs)      |
| `OPEN_SHEPHERD_PROXY_PORT` | `8787`                          | Listening port for `agent-hooks/antigravity-proxy-guard.mjs` |
| `OPEN_SHEPHERD_PROXY_HOST` | `127.0.0.1`                     | Bind address for `agent-hooks/antigravity-proxy-guard.mjs`   |
