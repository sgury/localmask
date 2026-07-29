// LocalMask — Key Toggle
// Flip the active editor between the real file and a read-only MASKED view.
// Masking runs 100% locally via the LocalMask CLI (`localmask mask-text`).

const vscode = require("vscode");
const cp = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const SCHEME = "localmask-masked";

function cliPath() {
  const p = vscode.workspace.getConfiguration("localmask").get("cliPath") || "~/.localmask/localmask";
  return p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
}

/** Find the scan id: explicit setting, then the LocalMask git hook, then
 *  ask the CLI for the repo's latest scan (`localmask scan-id <path>`). */
function findScanId(fileUri) {
  const cfg = vscode.workspace.getConfiguration("localmask").get("scanId");
  if (cfg) return cfg;
  const folder = vscode.workspace.getWorkspaceFolder(fileUri);
  if (!folder) return "";
  // LATEST scan first: chat/MCP/CLI actions always target the repo's newest
  // scan, so the UI must follow it — a scan id burned into an old git hook
  // otherwise leaves the tree/masked view showing stale data.
  try {
    const out = cp.execFileSync(cliPath(), ["scan-id", folder.uri.fsPath],
      { timeout: 10000 }).toString().trim();
    const id = out.split("\n").reverse().find((l) => l.startsWith("scan_"));
    if (id) return id;
  } catch (e) { /* CLI unavailable — fall back to the hook comment */ }
  for (const hook of ["post-commit", "pre-push"]) {
    const hookPath = path.join(folder.uri.fsPath, ".git", "hooks", hook);
    try {
      const m = fs.readFileSync(hookPath, "utf8").match(/# Scan ID: (\S+)/);
      if (m) return m[1];
    } catch (e) { /* no hook — keep looking */ }
  }
  return "";
}

function maskFile(scanId, filePath) {
  return new Promise((resolve, reject) => {
    cp.execFile(cliPath(), ["mask-text", scanId, filePath],
      { maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
        if (err) reject(new Error(stderr || err.message));
        else resolve(stdout);
      });
  });
}

/** localmask-masked:/real/path.py?<encoded real fsPath> */
function maskedUri(fileUri) {
  return vscode.Uri.from({
    scheme: SCHEME,
    path: fileUri.fsPath,
    query: encodeURIComponent(fileUri.fsPath),
  });
}

function realPathOf(uri) {
  return decodeURIComponent(uri.query);
}

function activate(context) {
  const emitter = new vscode.EventEmitter();
  let cliLabel = "";   // "CLI 0.9.9 pro" — set by the version probe

  // Masked-content cache keyed by real path — invalidated when the file's
  // mtime changes. The engine cold-starts in seconds; a re-flip must not.
  const cache = new Map();

  async function maskedContent(filePath) {
    if (!fs.existsSync(cliPath())) {
      return "// LocalMask: the CLI isn't installed yet (extension-only install).\n" +
             "// One command sets it up — 100% local, no account:\n" +
             "//   curl -sL https://localmaskpro.com/install-mcp.sh | bash\n" +
             "// Then click the shield in the status bar to scan.\n";
    }
    const scanId = findScanId(vscode.Uri.file(filePath));
    if (!scanId) {
      return "// LocalMask: no scan found for this repo yet.\n" +
             "// Ask your AI to \"scan this repo for secrets\", or run `localmask scan .`\n";
    }
    // No in-memory caching: the CLI serves from the persisted masked store
    // in ~0.5s, and review decisions (teach / reject) can change the masked
    // content without the file's mtime moving — a cache here shows stale
    // views right after a review.
    return await maskFile(scanId, filePath);
  }

  const provider = {
    onDidChange: emitter.event,
    async provideTextDocumentContent(uri) {
      try {
        return await maskedContent(realPathOf(uri));
      } catch (e) {
        return `// LocalMask: masking failed\n// ${String(e.message).trim().split("\n").join("\n// ")}\n`;
      }
    },
  };
  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider(SCHEME, provider));

  // ── Status bar key ────────────────────────────────────────────────
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 1000);
  status.command = "localmask.toggle";
  context.subscriptions.push(status);

  /** Uri of what the user is actually looking at — falls back to the active
   *  TAB when there is no active text editor (custom editors, e.g. CSV
   *  preview/table extensions), so the key works for every file. */
  function activeFileUri() {
    const ed = vscode.window.activeTextEditor;
    if (ed) return ed.document.uri;
    const grp = vscode.window.tabGroups.activeTabGroup;
    const tab = grp && grp.activeTab;
    if (tab && tab.input && tab.input.uri) return tab.input.uri;
    return null;
  }

  function updateStatus() {
    if (vscode.workspace.getConfiguration("localmask")
        .get("showStatusBarKey") === false) { status.hide(); return; }
    const uri = activeFileUri();
    if (!uri) { status.hide(); return; }
    if (uri.scheme === SCHEME) {
      status.text = "$(key) MASKED VIEW — click for real values";
      status.backgroundColor = undefined;
      status.tooltip = "You are viewing the masked version (what the AI sees). Click to return to real values (local).";
      status.show();
    } else if (uri.scheme === "file") {
      status.text = "$(key) REAL VALUES — click to mask";
      status.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
      status.tooltip = "You are viewing real secrets. Click to see the masked view (what the AI sees).";
      status.show();
    } else {
      status.hide();
    }
  }
  context.subscriptions.push(
    vscode.window.onDidChangeActiveTextEditor(updateStatus),
    vscode.window.tabGroups.onDidChangeTabs(updateStatus),
    vscode.window.tabGroups.onDidChangeTabGroups(updateStatus));
  updateStatus();

  // ── Shield: persistent indicator + "scan all" button ──────────────
  const shield = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  shield.command = "localmask.scan";
  shield.text = "$(shield) LocalMask";
  shield.tooltip = "Click to scan the repository for secrets (100% local)";
  shield.show();
  context.subscriptions.push(shield);

  /** Stage badge: the shield always tells you where you are —
   *  findings · ⏳ review / ✓ approved / 🚀 published. */
  function refreshShield() {
    try {
      const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
      if (!folder) return;
      const scanId = findScanId(folder.uri);
      if (!scanId) { shield.text = "$(shield) LocalMask"; return; }
      const p = path.join(os.homedir(), ".localmask", "scans", scanId + ".json");
      const d = JSON.parse(fs.readFileSync(p, "utf8"));
      const dets = d.detections || [];
      const pending = dets.filter((x) => !x.decision || x.decision === "pending").length;
      const stage = pending ? `⏳ ${pending} to review`
        : (d.status === "published" || d.publish_target) ? "🚀 published"
        : d.status === "approved" ? "✓ approved" : (d.status || "");
      shield.text = `$(shield) ${dets.length} findings · ${stage}`;
      shield.tooltip = `LocalMask — scan ${scanId}. Click for actions (sync, review, teach, approve, publish, hook). 100% local.` +
        (cliLabel ? ` ${cliLabel}` : "");
    } catch (e) { /* keep current badge */ }
  }

  const ANSI = /\x1b\[[0-9;]*m/g;

  /** Run the CLI streaming progress lines into a withProgress notification. */
  function runCli(args, cwd, progress, cancel) {
    return new Promise((resolve, reject) => {
      const child = cp.spawn(cliPath(), args, { cwd });
      if (cancel) cancel.onCancellationRequested(() => child.kill());
      let out = "";
      const onData = (buf) => {
        out += buf.toString();
        const lines = buf.toString().replace(ANSI, "").split("\n");
        for (const l of lines) {
          const t = l.trim();
          if (t && t.length < 90) progress.report({ message: t });
        }
      };
      child.stdout.on("data", onData);
      child.stderr.on("data", onData);
      child.on("close", (code) => {
        if (code !== 0 && !out) return reject(new Error(args[0] + " failed"));
        resolve(out.replace(ANSI, ""));
      });
      child.on("error", reject);
    });
  }

  /** Run a short CLI action with a progress toast; returns clean output. */
  async function runQuick(args, root, title) {
    return vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title, cancellable: true },
      (progress, cancel) => runCli(args, root, progress, cancel));
  }

  async function scanOrSync() {
      const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
      if (!folder) {
        vscode.window.showWarningMessage("LocalMask: open a folder first.");
        return;
      }
      const root = folder.uri.fsPath;
      const needsInit = !fs.existsSync(path.join(root, ".mcp.json"));
      // If this repo already has a scan, the shield SYNCs it in place —
      // same as the commit hook: token vault and review decisions are
      // preserved and the masked store refreshed. A full scan (new scan id)
      // only happens the first time.
      const existing = needsInit ? "" : findScanId(folder.uri);
      shield.text = "$(sync~spin) LocalMask: " +
        (needsInit ? "setting up…" : existing ? "syncing…" : "scanning…");
      cache.clear();
      try {
        const summary = await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: "🛡 LocalMask — " + (needsInit
              ? "setting up this repo, then scanning (nothing leaves this machine)"
              : existing
                ? "re-syncing scan (nothing leaves this machine)"
                : "scanning repository (nothing leaves this machine)"),
            cancellable: true,
          },
          async (progress, cancel) => {
            if (needsInit) {
              progress.report({ message: "initializing LocalMask (MCP for your AI)…" });
              await runCli(["init"], root, progress, cancel);
              progress.report({ message: "✓ initialized — starting scan…" });
            }
            if (existing) {
              shield.text = "$(sync~spin) LocalMask: syncing…";
              const clean = await runCli(["sync", existing], root, progress, cancel);
              return {
                dets: (clean.match(/Total:\s+(\d+) detections/) || [])[1],
                files: undefined,
                scanId: existing,
                newDets: (clean.match(/(\d+) new secret/) || [])[1],
                inited: false,
              };
            }
            shield.text = "$(sync~spin) LocalMask: scanning…";
            const clean = await runCli(
              ["scan", ".", "--sensitivity", "strict"], root, progress, cancel);
            return {
              dets: (clean.match(/Detections:\s+(\d+)/) || [])[1],
              files: (clean.match(/Files:\s+(\d+)/) || [])[1],
              scanId: (clean.match(/scan_\d+_[0-9a-f]+/) || [])[0],
              inited: needsInit,
            };
          });
        shield.text = summary.dets
          ? `$(shield) LocalMask: ${summary.dets} findings`
          : "$(shield) LocalMask";
        shield.tooltip = summary.scanId
          ? `Scan ${summary.scanId} — ${summary.dets} detections` +
            (summary.files ? ` in ${summary.files} files` : "") +
            ". Click to re-sync."
          : shield.tooltip;
        emitter.fire && cache.clear();
        if (summary.inited) {
          vscode.window.showInformationMessage(
            "🛡 LocalMask is set up — reload the window so your AI picks up the MCP tools.",
            "Reload Window").then((p) => {
              if (p === "Reload Window")
                vscode.commands.executeCommand("workbench.action.reloadWindow");
            });
        }
        if (summary.files === undefined) {
          // Sync path (existing scan, refreshed in place)
          if (summary.newDets) {
            vscode.window.showWarningMessage(
              `🛡 LocalMask: ${summary.newDets} NEW secret(s) since last sync — review before publishing.`);
          } else {
            vscode.window.showInformationMessage(
              `🛡 LocalMask: sync complete — ${summary.dets || 0} detections, decisions preserved.`);
          }
        } else if (summary.dets) {
          const pick = await vscode.window.showInformationMessage(
            `🛡 LocalMask: ${summary.dets} findings in ${summary.files} files — all masked locally.`,
            "Review in AI chat", "OK");
          if (pick === "Review in AI chat") {
            vscode.window.showInformationMessage(
              'Ask your AI: "Show me the review queue" — it renders the LocalMask review board.');
          }
        } else {
          vscode.window.showInformationMessage("🛡 LocalMask: scan complete.");
        }
      } catch (e) {
        shield.text = "$(shield) LocalMask";
        vscode.window.showErrorMessage(`LocalMask scan failed: ${String(e.message).slice(0, 200)}`);
      }
      refreshShield();
  }

  // ── Shield click: the LocalMask menu ──────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("localmask.scan", async () => {
      // Extension installed but CLI missing (fresh marketplace install):
      // clicking the shield starts the guided install instead of an ENOENT.
      if (!fs.existsSync(cliPath())) { probeCli(true); return; }
      const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
      if (!folder) {
        vscode.window.showWarningMessage("LocalMask: open a folder first.");
        return;
      }
      const root = folder.uri.fsPath;
      // First ever click (repo not set up / never scanned): one-click
      // setup+scan, no menu to get in the way.
      if (!fs.existsSync(path.join(root, ".mcp.json"))) return scanOrSync();
      const scanId = findScanId(folder.uri);
      if (!scanId) return scanOrSync();

      const pick = await vscode.window.showQuickPick([
        { action: "sync", label: "$(sync) Scan / sync now",
          description: "re-scan, preserve tokens & review decisions" },
        { action: "approve", label: "$(check-all) Approve all detections",
          description: "accept every masking decision" },
        { action: "publish", label: "$(rocket) Publish masked mirror",
          description: "push the masked repo — tokens only, no secrets" },
        { action: "review", label: "$(checklist) Review findings",
          description: "interactive review in the terminal (values stay local)" },
        { action: "teach", label: "$(mortar-board) Teach a missed secret",
          description: "type it hidden — never shown, never sent to any AI" },
        { action: "hook", label: "$(git-commit) Install commit hook",
          description: "auto-sync the masked mirror on every commit" },
      ], { title: "🛡 LocalMask (100% local)", placeHolder: `Scan ${scanId}` });
      if (!pick) return;

      try {
        if (pick.action === "sync") {
          await scanOrSync();
        } else if (pick.action === "approve") {
          const out = await runQuick(["approve-all", scanId], root,
            "🛡 LocalMask — approving all detections…");
          const m = out.match(/Approved all (\d+)/);
          vscode.window.showInformationMessage(
            m ? `🛡 LocalMask: approved all ${m[1]} detections — ready to publish.`
              : "🛡 LocalMask: approve-all finished.");
        } else if (pick.action === "publish") {
          const cfg = vscode.workspace.getConfiguration("localmask");
          const suggested = cfg.get("publishTarget") ||
            path.join(path.dirname(root), path.basename(root) + "-masked.git");
          const target = await vscode.window.showInputBox({
            prompt: "Masked mirror: local path or git URL (created if missing)",
            value: suggested,
          });
          if (!target) return;
          await cfg.update("publishTarget", target,
            vscode.ConfigurationTarget.Workspace);
          // Local path that doesn't exist yet → create the bare mirror,
          // as promised by the prompt (the CLI only pushes to existing ones).
          const expanded = target.startsWith("~")
            ? path.join(os.homedir(), target.slice(1)) : target;
          if (path.isAbsolute(expanded) && !fs.existsSync(expanded)) {
            cp.execFileSync("git", ["init", "--bare", expanded]);
          }
          const out = await runQuick(["publish", scanId, target], root,
            "🛡 LocalMask — publishing masked mirror (tokens only)…");
          if (out.includes("Published")) {
            vscode.window.showInformationMessage(
              `🛡 LocalMask: masked mirror published to ${target} — no secrets left this machine.`);
          } else if (/need review|not approved|approve-all/i.test(out)) {
            // The review gate held the publish — offer the one-click path
            // instead of dumping raw CLI text on the user.
            const pick2 = await vscode.window.showWarningMessage(
              "🛡 LocalMask: publish held — detections still need review.",
              "Approve all & publish", "Review first");
            if (pick2 === "Approve all & publish") {
              await runQuick(["approve-all", scanId], root,
                "🛡 LocalMask — approving all detections…");
              const out2 = await runQuick(["publish", scanId, target], root,
                "🛡 LocalMask — publishing masked mirror (tokens only)…");
              vscode.window.showInformationMessage(out2.includes("Published")
                ? `🛡 LocalMask: masked mirror published to ${target}.`
                : "LocalMask publish: " + out2.slice(-160));
            } else if (pick2 === "Review first") {
              const term = vscode.window.createTerminal({ name: "LocalMask Review", cwd: root });
              term.show();
              term.sendText(`${cliPath()} review ${scanId}`);
            }
          } else {
            const err = (out.match(/✗[^\n]*\n?[^\n]*/) || [out.slice(-200)])[0];
            vscode.window.showErrorMessage(`LocalMask publish: ${err}`);
          }
        } else if (pick.action === "review") {
          // The CLI's interactive reviewer — in the integrated terminal, so
          // real values stay between the user and their screen.
          const term = vscode.window.createTerminal({ name: "LocalMask Review", cwd: root });
          term.show();
          term.sendText(`${cliPath()} review ${scanId}`);
        } else if (pick.action === "teach") {
          const value = await vscode.window.showInputBox({
            prompt: "The exact secret value the scanner missed (stays local — never sent to any AI)",
            password: true,
          });
          if (!value) return;
          const subtype = await vscode.window.showInputBox({
            prompt: "Token type for it (e.g. DATABASE_NAME, API_KEY, PERSON_NAME)",
            value: "SECRET",
          });
          if (!subtype) return;
          // Remember the category — same as the right-click teach picker.
          try {
            const cfgLm = vscode.workspace.getConfiguration("localmask");
            const known = cfgLm.get("teachTypes") || [];
            const norm = subtype.trim().toUpperCase().replace(/[^A-Z0-9_]/g, "_");
            if (norm && norm !== "SECRET" && !known.includes(norm)) {
              await cfgLm.update("teachTypes", [...known, norm],
                vscode.ConfigurationTarget.Global);
            }
          } catch (e) { /* non-fatal */ }
          const out = await runQuick(["teach", scanId, value, "--subtype", subtype],
            root, "🛡 LocalMask — teaching (local re-scan)…");
          const ok = out.match(/✓ Found[^\n]*/);
          const already = out.match(/already\s+tracked[^\n]*/);
          vscode.window.showInformationMessage("🛡 LocalMask: " +
            (ok ? ok[0].replace(/✓ /, "") :
             already ? "value was already tracked — all occurrences masked." :
             "taught — see terminal output for details."));
        } else if (pick.action === "hook") {
          const out = await runQuick(["hook", scanId], root,
            "🛡 LocalMask — installing commit hook…");
          vscode.window.showInformationMessage(
            out.includes("✓")
              ? "🛡 LocalMask: commit hook installed — every commit auto-syncs the masked mirror."
              : "🛡 LocalMask: hook — " + out.slice(-160));
        }
      } catch (e) {
        vscode.window.showErrorMessage(
          `LocalMask ${pick.action} failed: ${String(e.message).slice(0, 200)}`);
      }
      refreshShield();
    }));

  // Show the current stage as soon as the window opens.
  refreshShield();

  // ═══════════════════════════════════════════════════════════════════
  //  In-editor review pack: detection model → diagnostics, quick fixes,
  //  decorations, real-vs-masked diff, on-save sync.
  //  STABILITY RULE: everything below is defensive — any failure logs to
  //  the output channel and degrades silently; it must never break the IDE.
  // ═══════════════════════════════════════════════════════════════════
  const logChan = vscode.window.createOutputChannel("LocalMask");
  context.subscriptions.push(logChan);
  const logErr = (where, e) => {
    try { logChan.appendLine(`[${where}] ${(e && e.stack) || e}`); } catch (_) {}
  };

  const workRoot = () => {
    const f = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
    return f ? f.uri.fsPath : "";
  };
  const relOf = (fsPath) => {
    const root = workRoot();
    if (!root) return "";
    const r = path.relative(root, fsPath);
    return r.startsWith("..") ? "" : r.split(path.sep).join("/");
  };

  // ── CLI version handshake ─────────────────────────────────────────
  // decide/teach --stdin need CLI ≥ 0.9.9. Older CLI (or one without
  // --version at all) → hide those surfaces + one-time upgrade hint;
  // toggle/shield/scan keep working on any CLI.
  const MIN_CLI = "0.9.9";
  const versionLt = (a, b) => {
    if (a === "dev") return false;             // dev tree = always current
    const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
    for (let i = 0; i < 3; i++) {
      if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0);
    }
    return false;
  };
  // Closed/air-gapped orgs override this with their internal mirror
  // (Settings → localmask.installCommand). The command NEVER runs
  // automatically — only when the user clicks "Install now".
  const installCmd = () =>
    vscode.workspace.getConfiguration("localmask").get("installCommand") ||
    "curl -sL https://localmaskpro.com/install-mcp.sh | bash";
  // cliState.missing → CLI not installed at all (fresh extension-only
  // install); .old → installed but pre-0.9.9. Edition (free/pro/team/ent)
  // rides along for display — the extension works identically on all
  // editions, so upgrading to Pro/Team just changes the label.
  const cliState = { missing: false, old: false, version: "", edition: "" };

  function offerInstall() {
    vscode.window.showInformationMessage(
      "🛡 LocalMask: the extension is installed, but the LocalMask CLI isn't. " +
      "One command sets it up (100% local, no account):",
      "Install now", "Copy command"
    ).then((pick) => {
      try {
        if (pick === "Install now") {
          const term = vscode.window.createTerminal({ name: "LocalMask Install" });
          term.show();
          term.sendText(installCmd());
        } else if (pick === "Copy command") {
          vscode.env.clipboard.writeText(installCmd());
          vscode.window.setStatusBarMessage("🛡 install command copied", 4000);
        }
      } catch (e) { logErr("offerInstall", e); }
    });
  }

  function probeCli(interactive) {
    try {
      const missingNow = !fs.existsSync(cliPath());
      cp.execFile(cliPath(), ["--version"], { timeout: 5000 },
        (err, stdout) => {
          try {
            const out = err ? "" : String(stdout).trim().split(/\s+/);
            const wasBroken = cliState.missing || cliState.old;
            cliState.version = out[0] || "";
            cliState.edition = out[1] || "";
            cliLabel = cliState.version
              ? `CLI ${cliState.version} ${cliState.edition}`.trim() : "";
            cliState.missing = missingNow || (!!err && !cliState.version);
            cliState.old = !cliState.missing &&
              (!cliState.version || versionLt(cliState.version, MIN_CLI));
            vscode.commands.executeCommand("setContext",
              "localmask.cliOld", cliState.old || cliState.missing);
            if (cliState.missing) {
              if (interactive || !context.globalState.get("lm.cliMissingNotified")) {
                context.globalState.update("lm.cliMissingNotified", true);
                offerInstall();
              }
            } else if (cliState.old) {
              const key = "lm.cliOldNotified." + cliState.version;
              if (!context.globalState.get(key)) {
                context.globalState.update(key, true);
                vscode.window.showInformationMessage(
                  "🛡 LocalMask CLI " + cliState.version + " is older than this " +
                  "extension — in-editor review is disabled. Update: " + installCmd());
              }
            } else if (wasBroken) {
              // Just became healthy (fresh install finished, or Pro/Team
              // upgrade replaced the CLI) — light everything up.
              vscode.window.setStatusBarMessage(
                `🛡 LocalMask CLI ready — ${cliState.version} ${cliState.edition}`, 6000);
              model.scanId = ""; model._resolvedAt = 0;
              loadModel();
              refreshShield();
            }
          } catch (e) { logErr("probeCli", e); }
        });
    } catch (e) { logErr("probeCli", e); }
  }
  probeCli(false);
  // Re-probe when an install/upgrade may have happened: the install terminal
  // closes, or the window regains focus (user ran the curl in another shell,
  // or activated a Pro/Team license).
  context.subscriptions.push(
    vscode.window.onDidCloseTerminal((t) => {
      if (t.name === "LocalMask Install") probeCli(false);
    }),
    vscode.window.onDidChangeWindowState((s) => {
      if (s.focused && (cliState.missing || cliState.old)) probeCli(false);
    }));

  // ── Detection model: one loader + one change event ────────────────
  const model = {
    scanId: "",
    byFile: new Map(),        // rel path -> [detections]
    total: 0, pending: 0,
    changed: new vscode.EventEmitter(),
    _resolvedAt: 0,
  };
  context.subscriptions.push(model.changed);

  function loadModel() {
    try {
      const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
      if (!folder) return;
      // findScanId can shell out — cache the resolution for 15s.
      const now = Date.now();
      if (!model.scanId || now - model._resolvedAt > 15000) {
        model.scanId = findScanId(folder.uri) || "";
        model._resolvedAt = now;
      }
      const byFile = new Map();
      let total = 0, pending = 0;
      if (model.scanId) {
        const p = path.join(os.homedir(), ".localmask", "scans", model.scanId + ".json");
        const d = JSON.parse(fs.readFileSync(p, "utf8"));
        for (const det of d.detections || []) {
          total++;
          if (!det.decision || det.decision === "pending") pending++;
          const files = det.files && det.files.length ? det.files : [det.file];
          for (const f of files) {
            if (!f) continue;
            const norm = String(f).replace(/\\/g, "/").replace(/^\.\//, "");
            if (!byFile.has(norm)) byFile.set(norm, []);
            byFile.get(norm).push(det);
          }
        }
      }
      model.byFile = byFile;
      model.total = total;
      model.pending = pending;
      model.changed.fire();
    } catch (e) {
      // Missing/corrupt scan JSON = "no scan" — never an error surface.
      model.byFile = new Map(); model.total = 0; model.pending = 0;
      model.changed.fire();
      logErr("loadModel", e);
    }
  }

  // Watch the scans dir (files are atomically replaced — watch the folder,
  // not the file) with a debounce; re-arm quietly if the dir vanishes.
  try {
    const scansDir = path.join(os.homedir(), ".localmask", "scans");
    let t = null;
    if (fs.existsSync(scansDir)) {
      const w = fs.watch(scansDir, () => {
        clearTimeout(t);
        t = setTimeout(() => { loadModel(); refreshShield(); }, 300);
      });
      w.on("error", (e) => logErr("fs.watch", e));
      context.subscriptions.push({ dispose: () => { try { w.close(); } catch (_) {} } });
    }
  } catch (e) { logErr("watch-setup", e); }

  // ── Diagnostics: pending detections in the Problems panel ─────────
  const MAX_FILE_DETS = 2000;   // stability cap — huge data files opt out
  const diags = vscode.languages.createDiagnosticCollection("localmask");
  context.subscriptions.push(diags);

  const featureOn = (key) =>
    vscode.workspace.getConfiguration("localmask").get(key) !== false;

  function refreshDiagnostics() {
    try {
      diags.clear();
      if (!featureOn("problemsPanel")) return;   // user opted out in settings
      const root = workRoot();
      if (!root) return;
      for (const [rel, dets] of model.byFile) {
        if (dets.length > MAX_FILE_DETS) continue;
        const list = [];
        for (const d of dets) {
          if (d.decision && d.decision !== "pending") continue;
          const line = Math.max(0, (d.line || 1) - 1);
          const v = String(d.value || "");
          const shortV = v.length > 24 ? v.slice(0, 21) + "…" : v;
          const diag = new vscode.Diagnostic(
            new vscode.Range(line, 0, line, 400),
            `LocalMask: ${d.type}` + (shortV ? ` "${shortV}"` : "") +
              ` → will be masked as ${d.token || "~[…]~"}`,
            vscode.DiagnosticSeverity.Warning);
          diag.source = "LocalMask";
          diag.code = d.det_id || "";
          list.push(diag);
        }
        if (list.length)
          diags.set(vscode.Uri.file(path.join(root, rel)), list);
      }
    } catch (e) { logErr("diagnostics", e); }
  }

  // ── Decorations: review state at a glance in the real file ────────
  const decoPending = vscode.window.createTextEditorDecorationType({
    backgroundColor: "rgba(255, 200, 60, 0.10)",
    overviewRulerColor: "rgba(255, 200, 60, 0.8)",
    overviewRulerLane: vscode.OverviewRulerLane.Right,
  });
  const decoApproved = vscode.window.createTextEditorDecorationType({
    backgroundColor: "rgba(80, 200, 120, 0.07)",
    after: { contentText: "  🛡 masked", color: "rgba(120,200,150,0.55)" },
  });
  const decoRejected = vscode.window.createTextEditorDecorationType({
    after: { contentText: "  ○ kept readable", color: "rgba(160,160,160,0.5)" },
  });
  context.subscriptions.push(decoPending, decoApproved, decoRejected);

  function refreshDecorations() {
    try {
      const on = featureOn("inlineHighlights");   // user opt-out in settings
      for (const ed of vscode.window.visibleTextEditors) {
        if (ed.document.uri.scheme !== "file") continue;
        if (!on) {
          ed.setDecorations(decoPending, []);
          ed.setDecorations(decoApproved, []);
          ed.setDecorations(decoRejected, []);
          continue;
        }
        const rel = relOf(ed.document.uri.fsPath);
        const dets = (rel && model.byFile.get(rel)) || [];
        if (dets.length > MAX_FILE_DETS || ed.document.lineCount > 100000) {
          ed.setDecorations(decoPending, []);
          ed.setDecorations(decoApproved, []);
          ed.setDecorations(decoRejected, []);
          continue;
        }
        const buckets = { pending: [], approved: [], rejected: [] };
        for (const d of dets) {
          const line = Math.max(0, Math.min((d.line || 1) - 1, ed.document.lineCount - 1));
          const range = ed.document.lineAt(line).range;
          const state = !d.decision || d.decision === "pending" ? "pending" : d.decision;
          (buckets[state] || buckets.pending).push({
            range,
            hoverMessage: `LocalMask ${state}: ${d.type} — the AI sees ${d.token || "~[…]~"}`,
          });
        }
        ed.setDecorations(decoPending, buckets.pending);
        ed.setDecorations(decoApproved, buckets.approved);
        ed.setDecorations(decoRejected, buckets.rejected);
      }
    } catch (e) { logErr("decorations", e); }
  }

  // ── decide: the local primitive behind quick fixes ────────────────
  function decide(verdict, rel, line, reason) {
    return new Promise((resolve) => {
      const args = ["decide", verdict, "--file", rel];
      if (line) args.push("--line", String(line));
      if (reason) args.push("--reason", reason);
      if (model.scanId) args.push("--scan", model.scanId);
      cp.execFile(cliPath(), args, { cwd: workRoot(), timeout: 30000 },
        (err, stdout, stderr) => {
          if (err) { logErr("decide", stderr || err); resolve(false); return; }
          resolve(true);
        });
    });
  }

  async function decideAndRefresh(verdict, fileUri, line, reason) {
    const rel = relOf(fileUri.fsPath);
    if (!rel) return;
    const ok = await decide(verdict, rel, line, reason);
    if (!ok) {
      vscode.window.showWarningMessage(
        "LocalMask: could not record the decision — see the LocalMask output log.");
      return;
    }
    loadModel();
    refreshShield();
    emitter.fire(maskedUri(fileUri));   // live masked views update instantly
    vscode.window.setStatusBarMessage(
      verdict === "approved" ? "🛡 LocalMask: masking approved"
        : "🛡 LocalMask: rejected — value stays readable", 4000);
  }

  context.subscriptions.push(
    vscode.commands.registerCommand("localmask.approveLine", (uri, line) =>
      decideAndRefresh("approved", uri, line).catch((e) => logErr("approveLine", e))),
    vscode.commands.registerCommand("localmask.rejectLine", async (uri, line) => {
      try {
        const reason = await vscode.window.showInputBox({
          prompt: "Why is this a false positive? (recorded locally — the model learns from it)",
          placeHolder: "e.g. synthetic demo data",
        });
        if (reason === undefined) return;   // Esc = cancel
        await decideAndRefresh("rejected", uri, line, reason || "");
      } catch (e) { logErr("rejectLine", e); }
    }));

  // ── Quick fixes on the diagnostics ────────────────────────────────
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider({ scheme: "file" }, {
      provideCodeActions(doc, range, ctx) {
        try {
          if (cliState.old || cliState.missing) return [];   // no `decide` available
          const mine = (ctx.diagnostics || []).filter((d) => d.source === "LocalMask");
          if (!mine.length) return [];
          const line = range.start.line + 1;
          const approve = new vscode.CodeAction(
            "🛡 Approve masking here", vscode.CodeActionKind.QuickFix);
          approve.command = { command: "localmask.approveLine",
            title: "approve", arguments: [doc.uri, line] };
          approve.diagnostics = mine;
          approve.isPreferred = true;
          const reject = new vscode.CodeAction(
            "🛡 Reject — false positive (stays readable)", vscode.CodeActionKind.QuickFix);
          reject.command = { command: "localmask.rejectLine",
            title: "reject", arguments: [doc.uri, line] };
          reject.diagnostics = mine;
          return [approve, reject];
        } catch (e) { logErr("codeActions", e); return []; }
      },
    }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));

  // ── Side-by-side: real vs masked ──────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("localmask.compare", async () => {
      try {
        const uri = activeFileUri();
        if (!uri) return;
        const real = uri.scheme === SCHEME ? vscode.Uri.file(realPathOf(uri)) : uri;
        if (real.scheme !== "file") return;
        await vscode.commands.executeCommand("vscode.diff",
          real, maskedUri(real),
          `${path.basename(real.fsPath)} — real ⇄ masked (what the AI sees)`);
      } catch (e) { logErr("compare", e); }
    }));

  // ── On-save sync: masked store follows your edits ─────────────────
  let saveTimer = null, syncing = false;
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      try {
        if (doc.uri.scheme !== "file" || !relOf(doc.uri.fsPath)) return;
        if (!vscode.workspace.getConfiguration("localmask").get("syncOnSave")) return;
        if (!model.scanId) return;
        clearTimeout(saveTimer);
        saveTimer = setTimeout(() => {
          if (syncing) return;
          syncing = true;
          cp.execFile(cliPath(), ["sync", model.scanId],
            { cwd: workRoot(), timeout: 120000, maxBuffer: 8 * 1024 * 1024 },
            (err) => {
              syncing = false;
              if (err) { logErr("syncOnSave", err); return; }
              loadModel();
              refreshShield();
            });
        }, 2000);
      } catch (e) { logErr("onSave", e); }
    }));

  // Wire refreshes: model change → diagnostics + decorations; editors change
  // → decorations only.
  // ── Sidebar review tree: file → detections, ✓/✗ inline ────────────
  const stateOf = (d) => (!d.decision || d.decision === "pending")
    ? "pending" : d.decision;
  const stateIcon = {
    pending: new vscode.ThemeIcon("circle-large-outline",
      new vscode.ThemeColor("editorWarning.foreground")),
    approved: new vscode.ThemeIcon("pass",
      new vscode.ThemeColor("testing.iconPassed")),
    rejected: new vscode.ThemeIcon("circle-slash"),
  };

  const tree = {
    _em: new vscode.EventEmitter(),
    get onDidChangeTreeData() { return this._em.event; },
    getChildren(node) {
      try {
        if (!node) {
          return [...model.byFile.entries()]
            .sort((a, b) => b[1].length - a[1].length)
            .map(([rel, dets]) => ({ kind: "file", rel, dets }));
        }
        if (node.kind === "file") {
          return node.dets
            .slice()
            .sort((a, b) => (a.line || 0) - (b.line || 0))
            .map((d) => ({ kind: "det", rel: node.rel, det: d }));
        }
        return [];
      } catch (e) { logErr("tree.children", e); return []; }
    },
    getTreeItem(node) {
      try {
        const root = workRoot();
        if (node.kind === "file") {
          const pend = node.dets.filter((d) => stateOf(d) === "pending").length;
          const it = new vscode.TreeItem(node.rel,
            vscode.TreeItemCollapsibleState.Collapsed);
          it.description = pend ? `${pend} pending · ${node.dets.length} total`
            : `all decided · ${node.dets.length}`;
          it.iconPath = vscode.ThemeIcon.File;
          it.resourceUri = vscode.Uri.file(path.join(root, node.rel));
          it.contextValue = "lmFile";
          return it;
        }
        const d = node.det;
        const st = stateOf(d);
        // Show the REAL value in the tree — this is the user's own screen,
        // exactly like the terminal reviewer; nothing here reaches any AI.
        const val = String(d.value || "");
        const short = val.length > 30 ? val.slice(0, 27) + "…" : val;
        const it = new vscode.TreeItem(short || `L${d.line || "?"}`);
        it.description = `${d.type} · L${d.line || "?"}` +
          (st === "pending" ? "" : ` · ${st === "approved" ? "masked" : "kept readable"}`);
        it.tooltip = `"${val}"\n${d.type} — ${st}\n` +
          `the AI sees: ${d.token || "~[…]~"}\nclick to jump to it in the file`;
        it.iconPath = stateIcon[st] || stateIcon.pending;
        it.contextValue = "lmDet-" + st;
        it.command = {
          command: "localmask.openDet", title: "open",
          arguments: [node],
        };
        return it;
      } catch (e) { logErr("tree.item", e); return new vscode.TreeItem("…"); }
    },
  };
  const treeView = vscode.window.createTreeView("localmaskReview",
    { treeDataProvider: tree });
  context.subscriptions.push(treeView);

  function refreshTreeBadge() {
    try {
      treeView.badge = model.pending
        ? { value: model.pending, tooltip: `${model.pending} detections pending review` }
        : undefined;
    } catch (e) { logErr("badge", e); }
  }

  const nodeFileUri = (node) =>
    vscode.Uri.file(path.join(workRoot(), node.rel));

  context.subscriptions.push(
    vscode.commands.registerCommand("localmask.refreshTree", () => {
      model.scanId = ""; model._resolvedAt = 0;   // force fresh resolution
      loadModel();
    }),
    // Open the file and SELECT the exact value on its line, so what's being
    // masked is unmistakable even with many findings around.
    vscode.commands.registerCommand("localmask.openDet", async (node) => {
      try {
        if (!node || !node.det) return;
        const d = node.det;
        const doc = await vscode.workspace.openTextDocument(nodeFileUri(node));
        const ed = await vscode.window.showTextDocument(doc, { preview: true });
        const lineNo = Math.max(0, Math.min((d.line || 1) - 1, doc.lineCount - 1));
        const text = doc.lineAt(lineNo).text;
        const val = String(d.value || "");
        let range;
        const col = val ? text.indexOf(val) : -1;
        if (col >= 0) {
          range = new vscode.Range(lineNo, col, lineNo, col + val.length);
        } else {
          // value not on that exact line (moved since scan) — try whole doc
          const idx = val ? doc.getText().indexOf(val) : -1;
          range = idx >= 0
            ? new vscode.Range(doc.positionAt(idx), doc.positionAt(idx + val.length))
            : doc.lineAt(lineNo).range;
        }
        ed.selection = new vscode.Selection(range.start, range.end);
        ed.revealRange(range, vscode.TextEditorRevealType.InCenter);
      } catch (e) { logErr("openDet", e); }
    }),
    vscode.commands.registerCommand("localmask.approveDet", (node) =>
      node && node.det && decideAndRefresh("approved", nodeFileUri(node), node.det.line)
        .catch((e) => logErr("approveDet", e))),
    vscode.commands.registerCommand("localmask.rejectDet", (node) =>
      node && node.det && vscode.commands.executeCommand(
        "localmask.rejectLine", nodeFileUri(node), node.det.line)),
    vscode.commands.registerCommand("localmask.approveFileNode", (node) =>
      node && decideAndRefresh("approved", nodeFileUri(node), 0)
        .catch((e) => logErr("approveFileNode", e))),
    vscode.commands.registerCommand("localmask.rejectFileNode", async (node) => {
      try {
        if (!node) return;
        const ok = await vscode.window.showWarningMessage(
          `Reject ALL detections in ${node.rel}? Every value there stays ` +
          "readable in the mirror (only in this file — the same values stay " +
          "masked elsewhere).", { modal: true }, "Reject file");
        if (ok === "Reject file")
          await decideAndRefresh("rejected", nodeFileUri(node), 0, "file review");
      } catch (e) { logErr("rejectFileNode", e); }
    }));

  // ── Right-click: approve/reject at cursor, teach by marking ───────
  /** The real file uri behind whatever editor is focused — the file itself,
   *  or the real path of a masked (diff) view. Null if neither. */
  function realFileUriOf(ed) {
    if (!ed) return null;
    const u = ed.document.uri;
    if (u.scheme === "file") return u;
    if (u.scheme === SCHEME) return vscode.Uri.file(realPathOf(u));
    return null;
  }

  context.subscriptions.push(
    // Works from the real file AND from the masked side of the diff view —
    // masked docs map back to their real file (same lines: tokens replace
    // values in place).
    vscode.commands.registerCommand("localmask.approveHere", () => {
      const ed = vscode.window.activeTextEditor;
      const uri = realFileUriOf(ed);
      if (!uri) return;
      return decideAndRefresh("approved", uri,
        ed.selection.active.line + 1).catch((e) => logErr("approveHere", e));
    }),
    vscode.commands.registerCommand("localmask.rejectHere", () => {
      const ed = vscode.window.activeTextEditor;
      const uri = realFileUriOf(ed);
      if (!uri) return;
      return vscode.commands.executeCommand("localmask.rejectLine",
        uri, ed.selection.active.line + 1);
    }),
    vscode.commands.registerCommand("localmask.teachSelection", async () => {
      try {
        const ed = vscode.window.activeTextEditor;
        const fileUri = realFileUriOf(ed);
        if (!fileUri) return;
        const value = ed.document.getText(ed.selection).trim();
        if (!value) {
          vscode.window.showInformationMessage(
            "LocalMask: select the exact secret value first, then right-click → Mark as secret.");
          return;
        }
        if (value.includes("~[")) {
          vscode.window.showInformationMessage(
            "LocalMask: that selection contains a masked token — it's already protected. " +
            "Select the raw value (real view) to teach.");
          return;
        }
        // User-defined categories (settings) first, then the built-ins.
        const custom = vscode.workspace.getConfiguration("localmask")
          .get("teachTypes") || [];
        const builtins = ["SECRET", "API_KEY", "PASSWORD", "TOKEN",
          "DATABASE_NAME", "PERSON_NAME", "EMAIL", "INTERNAL_URL"];
        const types = [...new Set([...custom, ...builtins])];
        const subtype = await vscode.window.showQuickPick(
          [...types, "Custom…"],
          { title: "🛡 Token type for this value (stays 100% local)" });
        if (!subtype) return;
        let st = subtype;
        if (subtype === "Custom…") {
          st = await vscode.window.showInputBox({ prompt: "Token type", value: "SECRET" });
          if (!st) return;
          st = st.trim().toUpperCase().replace(/[^A-Z0-9_]/g, "_");
          // Remember it: next time it's a first-class category in the picker.
          if (!custom.includes(st) && !builtins.includes(st)) {
            try {
              await vscode.workspace.getConfiguration("localmask").update(
                "teachTypes", [...custom, st],
                vscode.ConfigurationTarget.Global);
            } catch (err) { logErr("saveTeachType", err); }
          }
        }
        // Value goes over STDIN — never argv (no `ps`/history leak), never
        // anywhere near an AI.
        await new Promise((resolve) => {
          const child = cp.execFile(cliPath(),
            ["teach", model.scanId || "-", "--stdin", "--subtype", st],
            { cwd: workRoot(), timeout: 120000, maxBuffer: 8 * 1024 * 1024 },
            (err, stdout, stderr) => {
              if (err) {
                logErr("teachSelection", stderr || err);
                vscode.window.showWarningMessage(
                  "LocalMask: teach failed — see the LocalMask output log.");
              } else {
                vscode.window.setStatusBarMessage(
                  "🛡 LocalMask: taught — all occurrences will be masked", 4000);
              }
              resolve();
            });
          child.stdin.write(value);
          child.stdin.end();
        });
        model.scanId = ""; model._resolvedAt = 0;   // teach may follow a newer scan
        loadModel();
        refreshShield();
        emitter.fire(maskedUri(fileUri));
      } catch (e) { logErr("teachSelection", e); }
    }));

  // ── Per-button visibility (user settings) ─────────────────────────
  function applyVisibility() {
    try {
      if (featureOn("showStatusBarShield")) shield.show(); else shield.hide();
      updateStatus();   // key item re-evaluates its own setting
    } catch (e) { logErr("visibility", e); }
  }

  context.subscriptions.push(
    model.changed.event(() => {
      refreshDiagnostics();
      refreshDecorations();
      tree._em.fire();
      refreshTreeBadge();
    }),
    vscode.window.onDidChangeVisibleTextEditors(() => refreshDecorations()),
    // Settings changes apply immediately — no reload needed.
    vscode.workspace.onDidChangeConfiguration((e) => {
      try {
        if (e.affectsConfiguration("localmask")) {
          refreshDiagnostics();
          refreshDecorations();
          applyVisibility();
        }
      } catch (err) { logErr("configChange", err); }
    }));
  loadModel();
  applyVisibility();

  // ── The key toggle ────────────────────────────────────────────────
  context.subscriptions.push(
    vscode.commands.registerCommand("localmask.toggle", async () => {
      const log = () => {};
      try {
      let ed = vscode.window.activeTextEditor;
      if (!ed) {
        // Custom editor tab (e.g. a CSV table view): reopen as text so the
        // key works there too.
        const uri = activeFileUri();
        if (!uri || uri.scheme !== "file") return;
        const d = await vscode.workspace.openTextDocument(uri);
        ed = await vscode.window.showTextDocument(d, { preview: false });
      }
      const doc = ed.document;
      log("doc scheme=" + doc.uri.scheme + " path=" + doc.uri.fsPath);
      const line = ed.selection.active.line;

      let target;
      let newDoc;
      if (doc.uri.scheme === SCHEME) {
        target = vscode.Uri.file(realPathOf(doc.uri));        // masked -> real
        newDoc = await vscode.workspace.openTextDocument(target);
      } else if (doc.uri.scheme === "file") {
        // real -> masked: the local engine can take a few seconds on a cold
        // start — say so, visibly, instead of silently "thinking".
        status.text = "$(sync~spin) LocalMask: masking secrets locally…";
        status.backgroundColor = undefined;
        target = maskedUri(doc.uri);
        log("real->masked, warming cache");
        newDoc = await vscode.window.withProgress(
          {
            location: vscode.ProgressLocation.Notification,
            title: "🔒 LocalMask — masking secrets (100% local)…",
          },
          async () => {
            log("calling maskedContent");
            const warmed = await maskedContent(doc.uri.fsPath);   // warm the cache
            log("maskedContent ok len=" + (warmed || "").length);
            emitter.fire(target);                  // provider serves it instantly
            const od = await vscode.workspace.openTextDocument(target);
            log("openTextDocument ok");
            return od;
          });
      } else {
        return;
      }
      log("opening editor via vscode.open…");
      // vscode.window.showTextDocument can hang forever (observed on 1.9x
      // with virtual documents); the built-in open command is reliable.
      await vscode.commands.executeCommand("vscode.open", newDoc.uri,
        { preview: false });
      log("vscode.open ok");
      if (newDoc.uri.scheme === SCHEME) {
        // VS Code keeps closed virtual docs cached for minutes — re-opening
        // can serve pre-teach/pre-review content. Fire AFTER opening so the
        // now-visible doc is re-queried and always shows the current store.
        emitter.fire(newDoc.uri);
      }
      const newEd = vscode.window.activeTextEditor;
      if (newEd && newEd.document.uri.toString() === newDoc.uri.toString()) {
        // keep the same spot in the file
        const pos = new vscode.Position(Math.min(line, newDoc.lineCount - 1), 0);
        newEd.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        newEd.selection = new vscode.Selection(pos, pos);
      }

      // close only the previous view of this file so it feels like a flip
      const oldUri = doc.uri.toString();
      for (const group of vscode.window.tabGroups.all) {
        for (const tab of group.tabs) {
          if (tab.input && tab.input.uri && tab.input.uri.toString() === oldUri) {
            await vscode.window.tabGroups.close(tab);
          }
        }
      }
      updateStatus();
      } catch (e) {
        log("toggle ERROR: " + (e && e.stack || e));
        vscode.window.showErrorMessage("LocalMask toggle failed: " + String(e).slice(0, 200));
      }
    }));
}

function deactivate() {}

module.exports = { activate, deactivate };
