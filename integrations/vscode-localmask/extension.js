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
  for (const hook of ["post-commit", "pre-push"]) {
    const hookPath = path.join(folder.uri.fsPath, ".git", "hooks", hook);
    try {
      const m = fs.readFileSync(hookPath, "utf8").match(/# Scan ID: (\S+)/);
      if (m) return m[1];
    } catch (e) { /* no hook — keep looking */ }
  }
  try {
    return cp.execFileSync(cliPath(), ["scan-id", folder.uri.fsPath],
      { timeout: 10000 }).toString().trim();
  } catch (e) {
    return "";
  }
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

  // Masked-content cache keyed by real path — invalidated when the file's
  // mtime changes. The engine cold-starts in seconds; a re-flip must not.
  const cache = new Map();

  async function maskedContent(filePath) {
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
      shield.tooltip = `LocalMask — scan ${scanId}. Click for actions (sync, review, teach, approve, publish, hook). 100% local.`;
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
