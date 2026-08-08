/**
 * "Team Member" Demo — connects to the LIVE Cloudflare Worker
 *
 * This simulates a developer on your team who does NOT have LocalMask
 * installed. They just connect their MCP client to the Worker URL and
 * can read masked code + get AI reviews — without seeing any secrets.
 *
 * Usage:
 *   node team-member-demo.mjs [worker-url]
 *
 * Default: https://localmask-agent.localmask.workers.dev/mcp
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));

// Accept Worker URL from command line or use deployed default
const WORKER = process.argv[2] || "https://localmask-agent.localmask.workers.dev/mcp";
const REPO   = resolve(__dirname, "demo-repo");

const PAUSE = 3000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function hr(title) {
  console.log();
  console.log(`${"═".repeat(64)}`);
  console.log(`  ${title}`);
  console.log(`${"═".repeat(64)}`);
}

function showRequest(tool, args) {
  console.log();
  console.log("  ┌─ MCP Request ─────────────────────────────────");
  console.log(`  │  Tool:  ${tool}`);
  for (const [k, v] of Object.entries(args)) {
    const display = String(v).length > 50 ? String(v).slice(0, 47) + "..." : v;
    console.log(`  │  ${k}: ${display}`);
  }
  console.log("  └───────────────────────────────────────────────");
}

function showResponse(label, lines) {
  console.log();
  console.log(`  ┌─ ${label} ${"─".repeat(Math.max(0, 46 - label.length))}`);
  for (const line of lines) {
    console.log(`  │  ${line}`);
  }
  console.log("  └───────────────────────────────────────────────");
}

// ── Intro ─────────────────────────────────────────────────────
console.log();
console.log("  ╔══════════════════════════════════════════════════════════╗");
console.log("  ║   LocalMask + Cloudflare Worker — Team Access Demo      ║");
console.log("  ║   How team members connect to a shared MCP server       ║");
console.log("  ╚══════════════════════════════════════════════════════════╝");
console.log();
console.log("  SCENARIO: Your team lead deployed LocalMask behind a");
console.log("  Cloudflare Worker. You're a developer who needs to review");
console.log("  code with AI — without installing anything.");
console.log();

await sleep(PAUSE);

// ── How to connect ────────────────────────────────────────────
hr("HOW TEAM MEMBERS CONNECT");

console.log();
console.log("  All you need is the Worker URL. Add it to your MCP client:");
console.log();
console.log("  ┌─ Claude Desktop / Cursor / VS Code ─────────────");
console.log('  │  {');
console.log('  │    "mcpServers": {');
console.log('  │      "localmask": {');
console.log(`  │        "url": "${WORKER}"`);
console.log('  │      }');
console.log('  │    }');
console.log('  │  }');
console.log("  └─────────────────────────────────────────────────");
console.log();
console.log("  That's it. No Python. No pip install. No API keys.");
console.log("  One URL — works from any machine, any OS.");
console.log();
console.log("  Architecture:");
console.log("    Your laptop → Cloudflare Edge → tunnel → team's LocalMask");
console.log("    Secrets never leave the server. You only see ~[TOKEN]~.");

await sleep(PAUSE);

// ── Connect ───────────────────────────────────────────────────
hr("CONNECTING to remote MCP server");
console.log();
console.log(`  Worker URL: ${WORKER}`);
console.log("  Transport:  Streamable HTTP (MCP protocol)");
console.log("  Install:    NONE — just a URL");

const transport = new StreamableHTTPClientTransport(new URL(WORKER));
const client = new Client({ name: "team-member", version: "1.0.0" });
await client.connect(transport);

console.log("  Status:     ✓ Connected to Cloudflare Worker");

// List available tools
const { tools } = await client.listTools();
console.log(`  Tools:      ${tools.length} available`);
for (const t of tools) {
  console.log(`    • ${t.name}`);
}

await sleep(PAUSE);

// ── Step 1: Scan the repo ─────────────────────────────────────
hr("STEP 1 — Scan a repo through the Worker");

showRequest("scan_repo", { source: REPO, sensitivity: "strict" });

console.log();
console.log("  Scanning remotely... (Worker → tunnel → LocalMask → back)");

const scanResult = await client.callTool(
  { name: "scan_repo", arguments: { source: REPO, sensitivity: "strict" } },
  undefined,
  { timeout: 120_000 },
);
const scan = JSON.parse(scanResult.content[0].text);

const byType = scan.summary_stats?.by_type || {};
const responseLines = [
  `Scan ID:     ${scan.scan_id}`,
  `Files:       ${scan.summary_stats?.total_files}`,
  `Detections:  ${scan.summary_stats?.total_detections}`,
  ``,
  `Breakdown:`,
];
for (const [type, count] of Object.entries(byType)) {
  responseLines.push(`  • ${type}: ${count}`);
}
showResponse("MCP Response (from Cloudflare Edge)", responseLines);

await sleep(PAUSE);

// ── Step 2: Read masked code ──────────────────────────────────
hr("STEP 2 — Read masked code (never see real secrets)");

showRequest("get_file_masked", { scan_id: scan.scan_id, path: "src/payment_processor.py" });

const maskedResult = await client.callTool({
  name: "get_file_masked",
  arguments: { scan_id: scan.scan_id, path: "src/payment_processor.py" },
});
const masked = JSON.parse(maskedResult.content[0].text);
const allLines = masked.masked_content.split("\n");

const codeLines = [];
for (let i = 0; i < allLines.length; i++) {
  const line = allLines[i];
  if (line.includes("~[") || line.includes("api_key") || line.includes("stripe") ||
      line.includes("import") || line.includes("def ") || line.includes("class ") ||
      line.includes("Bearer") || line.includes("REDIS")) {
    const lineNum = String(i + 1).padStart(3);
    codeLines.push(`${lineNum} │ ${line}`);
  }
}
showResponse("Masked Code — what YOU see", codeLines);

console.log();
console.log("  You can review the full code logic — but every secret");
console.log("  is replaced with ~[TOKEN]~. You can't leak what you can't see.");

await sleep(PAUSE);

// ── Step 3: Read masked .env ──────────────────────────────────
hr("STEP 3 — Read the .env file (all secrets masked)");

showRequest("get_file_masked", { scan_id: scan.scan_id, path: ".env" });

const envResult = await client.callTool({
  name: "get_file_masked",
  arguments: { scan_id: scan.scan_id, path: ".env" },
});
const envData = JSON.parse(envResult.content[0].text);

const envLines = [];
for (const line of envData.masked_content.split("\n")) {
  if (line.trim()) envLines.push(line);
}
showResponse("Masked .env", envLines);

await sleep(PAUSE);

// ── Step 4: Ask AI to review ──────────────────────────────────
hr("STEP 4 — Ask AI to review (Pro feature, BYOK)");

const question = "What are the top 3 security issues in this payment code?";

showRequest("ask_about_scan", {
  scan_id: scan.scan_id,
  question,
  provider: "anthropic",
});

console.log();
console.log("  The AI receives ONLY masked code — never real secrets.");
console.log("  Waiting for AI response...");

let answer;
try {
  const askResult = await client.callTool(
    {
      name: "ask_about_scan",
      arguments: { scan_id: scan.scan_id, question, provider: "anthropic" },
    },
    undefined,
    { timeout: 120_000 },
  );
  const askData = JSON.parse(askResult.content[0].text);
  answer = askData.answer || askData.error || "No response";
} catch (e) {
  answer = `(AI step requires Pro license + API key on the server)`;
}

const answerLines = answer.split("\n").slice(0, 20);
showResponse("AI Review (via Cloudflare → LocalMask → Anthropic)", answerLines);
if (answer.split("\n").length > 20) {
  console.log(`  ... (${answer.split("\n").length} lines total)`);
}

await sleep(PAUSE);

// ── Done ──────────────────────────────────────────────────────
console.log();
console.log("  ╔══════════════════════════════════════════════════════════╗");
console.log("  ║  DONE                                                   ║");
console.log("  ║                                                         ║");
console.log("  ║  As a team member, you:                                 ║");
console.log("  ║  ✓ Connected to a remote MCP server (one URL)           ║");
console.log("  ║  ✓ Scanned a repo for secrets                          ║");
console.log("  ║  ✓ Read masked code — never saw real keys               ║");
console.log("  ║  ✓ Got AI review — AI never saw real keys either        ║");
console.log("  ║                                                         ║");
console.log("  ║  No Python. No LocalMask install. No secrets exposed.   ║");
console.log("  ║  Just one Worker URL.                                   ║");
console.log("  ╚══════════════════════════════════════════════════════════╝");
console.log();

await client.close();
