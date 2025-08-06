# Enterprise Policy GitOps

Manage VS Code / AI IDE extension and MCP policies declaratively using version-controlled allowlist and blocklist files.

## Files

- `allowed_publishers.txt`: One trusted publisher ID per line (e.g., `ms-vscode`).
- `allowed_extensions.txt`: One approved `publisher.extension` ID per line.
- `disallowed_extensions.txt`: One explicitly blocked `publisher.extension` ID per line (overrides publisher-level allows).

Lines starting with `#` and blank lines are ignored.

## Usage

Generate `vscodePolicy` (for Linux `/etc/vscode/policy.json` or macOS Managed Preferences) and `admxPolicy` (for Windows Intune/GPO):

```bash
open-shepherd policy generate docs/policy-gitops
```

Preview the impact of an allowlist against locally installed extensions:

```bash
open-shepherd policy impact --allowlist docs/policy-gitops/allowed_publishers.example.txt
```

Audit active enterprise policies on the current host:

```bash
open-shepherd policy audit
```
