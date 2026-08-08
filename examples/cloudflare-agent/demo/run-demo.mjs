/**
 * Real-World Scenario: A developer wants AI to review their payment code
 * for security issues — but the code has production Stripe keys, database
 * passwords, and API tokens hardcoded.
 *
 * Without LocalMask: those secrets go straight to the AI provider.
 * With LocalMask via Cloudflare Worker: secrets are masked locally,
 * AI only sees ~[TOKEN]~ placeholders.
 *
 * Usage:
 *   1. bash setup-demo-repo.sh        ← creates the fake fintech repo
 *   2. Start LocalMask:  cd ../../.. && python3 -m uvicorn server:app --port 8787
 *   3. Start Worker:     cd .. && npm install && npx wrangler dev --port 8788
 *   4. node run-demo.mjs              ← run this script (record your terminal)
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { fileURLToPath } from "url";
import { dirname, resolve } from "path";

const __dirname = dirname(fileURLToPath(import.meta.url));

const WORKER = "http://localhost:8788/mcp";
const REPO   = resolve(__dirname, "demo-repo");

// ── Video-friendly helpers ────────────────────────────────────
const PAUSE = 3000;  // ms between segments — enough to read each section

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
console.log("  ║        LocalMask + Cloudflare Worker Demo               ║");
console.log("  ║  AI reviews your code — without seeing your secrets     ║");
console.log("  ╚══════════════════════════════════════════════════════════╝");
console.log();
console.log("  SCENARIO: You're a developer at Meridian Payments.");
console.log("  You want Claude to review your Stripe integration code.");
console.log("  Problem: the code has production API keys hardcoded.");
console.log("  Solution: LocalMask scans & masks via a Cloudflare Worker.");
console.log();
console.log("  Architecture:");
console.log("    MCP Client → Cloudflare Worker (edge) → LocalMask (local)");
console.log("    Secrets never leave your machine.");

await sleep(PAUSE);

// ── Connect ───────────────────────────────────────────────────
hr("CONNECTING to Cloudflare Worker MCP server");
console.log();
console.log(`  Endpoint: ${WORKER}`);
console.log("  Transport: Streamable HTTP (MCP protocol)");

const transport = new StreamableHTTPClientTransport(new URL(WORKER));
const client = new Client({ name: "meridian-dev", version: "1.0.0" });
await client.connect(transport);

console.log("  Status: ✓ Connected");

await sleep(PAUSE);

// ══════════════════════════════════════════════════════════════
// STEP 1: Scan the repo
// ══════════════════════════════════════════════════════════════
hr("STEP 1 — Scan the payment repo for secrets");

showRequest("scan_repo", { source: REPO, sensitivity: "strict" });

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
showResponse("MCP Response", responseLines);

await sleep(PAUSE);

// ══════════════════════════════════════════════════════════════
// STEP 2: What secrets were found?
// ══════════════════════════════════════════════════════════════
hr("STEP 2 — What secrets were found?");

showRequest("get_detections", { scan_id: scan.scan_id });

const detsResult = await client.callTool({
  name: "get_detections",
  arguments: { scan_id: scan.scan_id },
});
const dets = JSON.parse(detsResult.content[0].text);

const detLines = [
  `${"TOKEN".padEnd(30)} ${"FILE".padEnd(28)} CONF`,
  `${"─".repeat(30)} ${"─".repeat(28)} ${"─".repeat(4)}`,
];
for (const d of dets.detections || []) {
  const conf = `${(d.confidence * 100).toFixed(0)}%`;
  detLines.push(`${d.token.padEnd(30)} ${d.file.padEnd(28)} ${conf}`);
}
showResponse("MCP Response — Detections", detLines);

await sleep(PAUSE);

// ══════════════════════════════════════════════════════════════
// STEP 3: Read the masked payment processor
// ══════════════════════════════════════════════════════════════
hr("STEP 3 — Read masked payment code (what AI sees)");

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
  if (line.includes("~[") || line.includes("api_key") || line.includes("SECRET") ||
      line.includes("REDIS") || line.includes("Bearer") || line.includes("stripe") ||
      line.includes("import") || line.includes("def ") || line.includes("class ")) {
    const lineNum = String(i + 1).padStart(3);
    codeLines.push(`${lineNum} │ ${line}`);
  }
}
showResponse("MCP Response — Masked Code (key lines)", codeLines);

console.log();
console.log("  Notice: every real secret is now a ~[TOKEN]~ placeholder.");
console.log("  The code structure and logic are fully intact for AI review.");

await sleep(PAUSE);

// ══════════════════════════════════════════════════════════════
// STEP 4: Read the masked .env
// ══════════════════════════════════════════════════════════════
hr("STEP 4 — The .env file (every secret masked)");

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
showResponse("MCP Response — Masked .env", envLines);

await sleep(PAUSE);

// ══════════════════════════════════════════════════════════════
// STEP 5: Side-by-side comparison
// ══════════════════════════════════════════════════════════════
hr("STEP 5 — What the AI sees vs. reality");

const stripeToken = (dets.detections || []).find(d => d.type.includes("stripe"))?.token || "~[STRIPE_SECRET_KEY_0]~";
const dbToken = (dets.detections || []).find(d => d.type.includes("database"))?.token || "~[DATABASE_URL_0]~";

console.log();
console.log("  ┌─ WITHOUT LocalMask (leaked to AI) ──────────────");
console.log('  │  stripe.api_key = "sk_live_51N8xRtKj3Qm7vL9..."');
console.log('  │  DATABASE_URL   = "postgresql://admin:Pr0d_DB..."');
console.log("  │");
console.log("  │  ⚠  Real production credentials sent to AI provider!");
console.log("  └─────────────────────────────────────────────────");
console.log();
console.log("  ┌─ WITH LocalMask (what AI actually receives) ────");
console.log(`  │  stripe.api_key = "${stripeToken}"`);
console.log(`  │  DATABASE_URL   = "${dbToken}"`);
console.log("  │");
console.log("  │  ✓  Opaque placeholders — AI can review logic,");
console.log("  │     but can't see or leak your secrets.");
console.log("  └─────────────────────────────────────────────────");

await sleep(PAUSE);

// ══════════════════════════════════════════════════════════════
// STEP 6: Ask AI to review the code
// ══════════════════════════════════════════════════════════════
hr("STEP 6 — AI reviews the masked code");

const question = "Review this payment processing code for security issues, error handling gaps, and best practices. Be specific about what to fix.";

showRequest("ask_about_scan", {
  scan_id: scan.scan_id,
  question,
  provider: "anthropic",
});

console.log();
console.log("  Waiting for AI response...");
console.log("  (AI only sees ~[TOKEN]~ placeholders, never real keys)");

let answer;
try {
  const askResult = await client.callTool(
    {
      name: "ask_about_scan",
      arguments: {
        scan_id: scan.scan_id,
        question,
        provider: "anthropic",
      },
    },
    undefined,
    { timeout: 120_000 },
  );
  const askData = JSON.parse(askResult.content[0].text);
  answer = askData.answer || askData.error || "No response";
} catch (e) {
  answer = `(AI step failed: ${e.message})\n\nTo enable this step, set your Anthropic API key:\n  localmask set-key anthropic YOUR_KEY`;
}

const answerLines = answer.split("\n");
const displayLines = answerLines.slice(0, 30);
showResponse("MCP Response — AI Review", displayLines);
if (answerLines.length > 30) {
  console.log(`  ... (${answerLines.length} lines total)`);
}

await sleep(PAUSE);

// ══════════════════════════════════════════════════════════════
// DONE
// ══════════════════════════════════════════════════════════════
console.log();
console.log("  ╔══════════════════════════════════════════════════════════╗");
console.log("  ║  DONE — AI reviewed the code with full context,         ║");
console.log("  ║  but never saw a single real secret.                    ║");
console.log("  ║                                                         ║");
console.log("  ║  Secrets stayed on your machine.                        ║");
console.log("  ║  Masking happened locally via LocalMask.                ║");
console.log("  ║  The Cloudflare Worker bridged MCP ↔ REST.              ║");
console.log("  ╚══════════════════════════════════════════════════════════╝");
console.log();

await client.close();
