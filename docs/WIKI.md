# Open-Shepherd Wiki

## 1. What It Can Do & What It Monitors

### VS Code Family (VS Code, Cursor, Windsurf, VSCodium, Antigravity, Trae)

- **Runtime API Monitoring** (`src/monitor/`): Hooks `http`/`https`, `child_process`, `fs`/`fs/promises`, and `vscode.tasks` inside the extension host.
- **Threat Detection & Blocking** (`src/detection/`): Evaluates network requests, spawned processes, sensitive file reads/writes (e.g., `~/.ssh`, `~/.aws/credentials`, `/etc/passwd`), and workspace tasks against security rules, blocking policy violations.
- **Extension Scanner** (`src/scanner/`): Inspects installed extension metadata and source code for suspicious patterns.
- **Allowlists & Trusted Publishers**: Lets you allowlist specific extensions or publishers.
- **Universal Event Output**: Emits structured `SecurityEvent`s to `~/.open-shepherd/events.jsonl` and optionally `OPEN_SHEPHERD_WEBHOOK`.

### Neovim (`>= 0.9`)

- **Terminal & Sensitive File Logging** (`neovim-plugin/`): Logs `TermOpen` and `BufWritePost` events for `.env`, `.ssh`, and `id_rsa` paths to `~/.open-shepherd/events.jsonl`.

### AI CLI Agents (Claude Code, etc.)

- **Tool-Use Audit Trail** (`agent-hooks/shepherd-hook.mjs`): Logs hook events (`PreToolUse`, `PostToolUse`, etc.) with truncated `tool_input` summaries (`command`, `file_path`, `url`, `path`, `pattern`) to `~/.open-shepherd/events.jsonl` and optional webhook.

---

## 2. What It Cannot Do & What It Is Not For

- **Not an OS-level EDR / Antivirus**: In VS Code, hooks only cover Node.js APIs inside the extension host. Native binaries, external terminals, or processes outside the IDE are not monitored.
- **Neovim & AI CLI hooks are audit-only**: They log events for visibility and forensics; they do **not** block commands or file writes.
- **Not a Sandbox or Firewall**: It complements—but does not replace—OS user permissions, containers, or network firewalls.
- **No Datadog Telemetry by Default**: Datadog Agent polling and OCSF submission are disabled unless `ide-shepherd.datadog.isEnabled` is explicitly set to `true`.

---

## 3. Architecture

Open-Shepherd keeps the upstream VS Code extension layout at the repository root (`src/`) so updates from `DataDog/IDE-SHEPHERD-extension` merge cleanly via [`.github/workflows/sync-upstream.yml`](../.github/workflows/sync-upstream.yml).

All adapters emit a unified JSONL event format to `~/.open-shepherd/events.jsonl` (overridable via `OPEN_SHEPHERD_LOG`) and optionally POST events to `OPEN_SHEPHERD_WEBHOOK`.

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

## 2. Setup by IDE / Agent

### VS Code, Cursor, Windsurf, VSCodium, Antigravity

```bash
npm install
npm run compile
```

Package or sideload the extension as a `.vsix`, or run it in Extension Development Host (`F5`).

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

---

## 3. Environment Variables

| Variable                | Default                         | Description                                      |
| ----------------------- | ------------------------------- | ------------------------------------------------ |
| `OPEN_SHEPHERD_LOG`     | `~/.open-shepherd/events.jsonl` | Path to local JSONL event log                    |
| `OPEN_SHEPHERD_WEBHOOK` | _(unset)_                       | Optional HTTP(S) endpoint for `POST` JSON events |
