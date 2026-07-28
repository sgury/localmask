# LocalMask for JetBrains IDEs (MVP)

PyCharm · IntelliJ IDEA · DataGrip · GoLand · WebStorm — platform APIs only.

- **🛡 status-bar shield** — findings + review stage; click for the action
  menu: scan/sync, approve all, publish masked mirror, review, commit hook.
- **🔑 masked view** (`Cmd+Alt+K` / right-click → *LocalMask: Show Masked
  View*) — read-only view of the current file exactly as the AI sees it.

Requires the free LocalMask CLI in `~/.localmask`
(`curl -sL https://localmaskpro.com/install-mcp.sh | bash`).

## Build / run

```bash
./gradlew buildPlugin      # → build/distributions/localmask-jetbrains-0.1.0.zip
./gradlew runIde           # sandboxed IDE with the plugin loaded
```

Install in your IDE: Settings → Plugins → ⚙ → Install Plugin from Disk → the zip.

Roadmap: inspections (Problems-panel equivalent) + intention actions
(approve/reject quick fixes) driven by `localmask decide`, mirroring the
VS Code extension.
