# Open-Shepherd Wiki

## 1. Architecture

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

---

## 4. Upstream Sync

[`.github/workflows/sync-upstream.yml`](../.github/workflows/sync-upstream.yml) runs weekly (Mondays 06:00 UTC) or manually via `workflow_dispatch` to open a PR when `DataDog/IDE-SHEPHERD-extension` has new commits.
