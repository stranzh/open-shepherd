# Open Shepherd CI, Git Hooks, and Pre-Clone Scanning

Run Open Shepherd headlessly in Git hooks, CI pipelines, and pre-clone workflows to catch poisoned workspace configs, malicious MCP servers, unsafe lifecycle hooks, and prompt-injected AI agent instruction files before any IDE or agent opens the repository.

## CLI Quick Reference

```bash
# Build the CLI entrypoint (./out/cli/index.js)
npm ci && npm run compile

# Scan current directory (outputs JSONL; exits 1 on HIGH severity findings)
node ./out/cli/index.js scan .

# Scan workspace + user global AI/IDE configs and emit SARIF
open-shepherd scan . --global --format sarif > open-shepherd.sarif

# Scan a remote GitHub repository over the GitHub API without cloning
open-shepherd scan-repo https://github.com/owner/repo --format jsonl

# Audit enterprise VS Code policies, evaluate allowlist impact, or compile GitOps policy manifests
open-shepherd policy audit
open-shepherd policy impact --allowlist docs/policy-gitops/allowed_extensions.example.txt
open-shepherd policy generate docs/policy-gitops

# Collect OCSF Inventory Info (class_uid 5001) and optionally forward over Syslog (udp/tcp/tls)
open-shepherd scan --inventory
open-shepherd scan . --format cef --syslog udp://127.0.0.1:514
```

- **Formats (`--format`)**: `jsonl` (default), `sarif`, `ocsf`, `cef`
- **Exit codes**:
  - `0`: No `high` severity findings
  - `1`: One or more `high` severity findings detected
  - `2`: Invalid arguments, URL validation error, or API/IO failure

---

## 1. Git `pre-commit` Hook

Add the following script to `.git/hooks/pre-commit` (and run `chmod +x .git/hooks/pre-commit`) or `.husky/pre-commit` to block commits when workspace or AI configs trigger `HIGH` severity findings:

```sh
#!/usr/bin/env sh
set -eu

# Run Open Shepherd against staged/workspace configuration files
# Exits 1 if any HIGH severity finding is detected.
if command -v open-shepherd >/dev/null 2>&1; then
  open-shepherd scan . --format jsonl
else
  node ./out/cli/index.js scan . --format jsonl
fi
```

If you want to run the check only when relevant config files are staged:

```sh
#!/usr/bin/env sh
set -eu

STAGED_CONFIGS=$(git diff --cached --name-only --diff-filter=ACMR | grep -E '(^|/)(\.vscode/|\.devcontainer/|\.claude/|\.cursor/|\.cursorrules|\.agents/|\.agent/|\.kiro/|\.codex/|\.trae/|\.qoder/|\.zed/|\.opencode/|opencode\.json|package\.json|\.npmrc|pip\.conf|\.mcp\.json|mcp\.json|mcp_config\.json|CLAUDE\.md|AGENTS\.md|AGENTS\.override\.md|GEMINI\.md|SKILL\.md|\.windsurfrules|\.clinerules|\.github/copilot-instructions\.md|\.gitmodules|\.husky/|\.pre-commit-config\.yaml)' || true)

if [ -n "$STAGED_CONFIGS" ]; then
  npx --no-install open-shepherd scan . --format jsonl
fi
```

---

## 2. `.pre-commit-config.yaml` Local Hook

For repositories using [pre-commit](https://pre-commit.com/), register Open Shepherd as a local hook in `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: open-shepherd-scan
        name: Open Shepherd Workspace & AI Config Scan
        entry: open-shepherd scan . --format jsonl
        language: system
        pass_filenames: false
        always_run: true
```

---

## 3. GitHub Actions Workflow (SARIF Upload)

Create `.github/workflows/open-shepherd.yml` to scan pull requests and pushes, upload results to GitHub Code Scanning via `github/codeql-action/upload-sarif`, and fail the job on `HIGH` severity findings:

```yaml
name: Open Shepherd Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  open-shepherd:
    name: Workspace & AI Config Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Open Shepherd
        run: npm install -g open-shepherd

      - name: Scan repository and generate SARIF
        id: scan
        continue-on-error: true
        run: |
          set +e
          open-shepherd scan . --format sarif > open-shepherd.sarif
          echo "exit_code=$?" >> "$GITHUB_OUTPUT"

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: open-shepherd.sarif
          category: open-shepherd

      - name: Fail on HIGH severity findings
        if: steps.scan.outputs.exit_code != '0'
        run: exit "${{ steps.scan.outputs.exit_code }}"
```

---

## 4. Pre-Clone GitHub Repository Gating (`scan-repo`)

Audit unfamiliar third-party repositories **before** running `git clone` or opening them in an IDE. `scan-repo` fetches the repository tree and risky config files strictly in memory over `https://api.github.com`—nothing is cloned or written to disk.

```bash
# Scan default branch using an owner/repo slug or full GitHub URL
open-shepherd scan-repo owner/untrusted-repo

# Pin to a specific branch, tag, or commit SHA and emit SARIF
open-shepherd scan-repo https://github.com/owner/untrusted-repo/tree/main --format sarif

# Pass a GitHub token for private repos or higher API rate limits (or set GITHUB_TOKEN / GH_TOKEN)
GITHUB_TOKEN=ghp_xxx open-shepherd scan-repo owner/private-repo --ref v1.2.0 --format jsonl
```

Example shell wrapper to gate `git clone`:

```sh
#!/usr/bin/env sh
set -eu

REPO="$1"
open-shepherd scan-repo "$REPO" --format jsonl
git clone "$REPO"
```

---

## 5. Protecting AI & IDE Configs with `.github/CODEOWNERS`

Require security-team review whenever a pull request adds or modifies AI agent instructions, MCP configurations, IDE settings, or devcontainer definitions. Add these rules to `.github/CODEOWNERS`:

```text
# Require security review on AI agent instructions, MCP configs, and IDE execution settings
AGENTS.md               @your-org/security-team
AGENTS.override.md      @your-org/security-team
CLAUDE.md               @your-org/security-team
GEMINI.md               @your-org/security-team
.cursor/                @your-org/security-team
.cursorrules            @your-org/security-team
.claude/                @your-org/security-team
.agents/                @your-org/security-team
.vscode/                @your-org/security-team
.devcontainer/          @your-org/security-team
.mcp.json               @your-org/security-team
.github/copilot-instructions.md @your-org/security-team
```
