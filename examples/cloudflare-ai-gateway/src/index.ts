/**
 * LocalMask + Cloudflare AI Gateway Worker (Pro Edition)
 *
 * Two-layer security for AI code review:
 *   Layer 1: LocalMask masks all secrets → ~[TOKEN]~ placeholders
 *   Layer 2: AI Gateway DLP catches anything masking missed → blocks the request
 *
 * Architecture:
 *   MCP Client → this Worker → LocalMask (masking only)
 *                     │
 *                     └→ builds prompt with masked code
 *                     └→ AI Gateway (DLP, cache, rate limit)
 *                     └→ Anthropic
 *
 * The Worker handles the AI call directly (not LocalMask), routing through
 * AI Gateway for DLP inspection, caching, and analytics.
 *
 * Requires LocalMask Pro — the Anthropic API key is managed server-side
 * and never exposed to clients or transmitted through the tunnel.
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

interface Env {
  LOCALMASK_API_URL: string;
  LOCALMASK_API_KEY?: string;
  AI_GATEWAY_URL: string;       // e.g. https://gateway.ai.cloudflare.com/v1/{account}/localmask
  AI_GATEWAY_TOKEN?: string;    // AI Gateway auth token (if authenticated gateway)
  ANTHROPIC_API_KEY: string;    // for calling Anthropic through the gateway
  ALLOW_LOCAL_PATHS?: string;
}

// Same system prompt as LocalMask Pro (localmask/askai.py)
const SYSTEM_PROMPT = `\
You are a code reviewer analysing a masked repository.
Sensitive values have been replaced with tokens like ~[PASSWORD_0]~, ~[INTERNAL_API_URL_1]~, etc.
Rules:
- Reference tokens by name when discussing sensitive values (e.g. "the password at ~[PASSWORD_0]~")
- Never guess or invent real values behind tokens
- Be concise — bullet points preferred, no padding
- The user will translate tokens back to real values locally after you answer`;

async function callLocalMask(
  env: Env,
  method: string,
  path: string,
  body?: Record<string, unknown>
): Promise<unknown> {
  const url = `${env.LOCALMASK_API_URL.replace(/\/$/, "")}${path}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (env.LOCALMASK_API_KEY) {
    headers["Authorization"] = `Bearer ${env.LOCALMASK_API_KEY}`;
  }

  const res = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const errText = await res.text();
    let errMsg: string;
    try {
      const errJson = JSON.parse(errText);
      errMsg = errJson.error || errText;
    } catch {
      errMsg = errText;
    }
    return { error: errMsg, status: res.status };
  }
  return res.json();
}

async function callAIGateway(
  env: Env,
  messages: { role: string; content: string }[]
): Promise<{ answer?: string; error?: string; gateway_blocked?: boolean }> {
  // AI Gateway proxies to Anthropic: append /anthropic to the gateway URL
  const gatewayUrl = `${env.AI_GATEWAY_URL.replace(/\/$/, "")}/anthropic`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "x-api-key": env.ANTHROPIC_API_KEY,
    "anthropic-version": "2023-06-01",
  };
  if (env.AI_GATEWAY_TOKEN) {
    headers["cf-aig-authorization"] = `Bearer ${env.AI_GATEWAY_TOKEN}`;
  }

  const res = await fetch(`${gatewayUrl}/v1/messages`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model: "claude-haiku-4-5-20251001",
      max_tokens: 2048,
      system: SYSTEM_PROMPT,
      messages,
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    // AI Gateway DLP returns 400 when it blocks a request
    if (res.status === 400 || res.status === 403) {
      return {
        error: errText,
        gateway_blocked: true,
      };
    }
    return { error: `AI Gateway error (${res.status}): ${errText}` };
  }

  const data = (await res.json()) as {
    content?: { type: string; text: string }[];
  };
  const text = data.content?.[0]?.text || "No response";
  return { answer: text };
}

function textResult(data: unknown): { content: { type: "text"; text: string }[] } {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

export class LocalMaskGatewayMCP extends McpAgent<Env> {
  server = new McpServer({
    name: "LocalMask + AI Gateway (Pro)",
    version: "1.0.0",
  });

  async init() {
    // ── scan_repo ──────────────────────────────────────────────
    this.server.tool(
      "scan_repo",
      "Scan a repository for secrets. Pass a git URL (or local path if ALLOW_LOCAL_PATHS is enabled).",
      {
        source: z.string().describe("Git URL to scan"),
        sensitivity: z
          .enum(["minimal", "standard", "strict"])
          .default("standard")
          .describe("Detection sensitivity level"),
      },
      async ({ source, sensitivity }) => {
        const isLocalPath = !source.startsWith("http://") &&
                            !source.startsWith("https://") &&
                            !source.startsWith("git@");
        if (isLocalPath && this.env.ALLOW_LOCAL_PATHS !== "true") {
          return textResult({
            error: "Local paths disabled. Use a git URL, or set ALLOW_LOCAL_PATHS=true for local dev.",
          });
        }
        const data = await callLocalMask(this.env, "POST", "/api/repos/scan", {
          repo_url: source,
          sensitivity,
        });
        return textResult(data);
      }
    );

    // ── get_detections ─────────────────────────────────────────
    this.server.tool(
      "get_detections",
      "Get all detections from a scan.",
      { scan_id: z.string().describe("Scan ID from scan_repo") },
      async ({ scan_id }) => {
        const data = await callLocalMask(this.env, "GET", `/api/repos/${scan_id}/detections`);
        return textResult(data);
      }
    );

    // ── get_file_masked ────────────────────────────────────────
    this.server.tool(
      "get_file_masked",
      "Read a file with secrets replaced by ~[TOKEN]~ placeholders.",
      {
        scan_id: z.string().describe("Scan ID"),
        path: z.string().optional().describe("File path (omit to list files)"),
      },
      async ({ scan_id, path }) => {
        const query = path ? `?path=${encodeURIComponent(path)}` : "";
        const data = await callLocalMask(this.env, "GET", `/api/repos/${scan_id}/files${query}`);
        return textResult(data);
      }
    );

    // ── ask_about_scan (AI call through AI Gateway) ────────────
    this.server.tool(
      "ask_about_scan",
      "Ask AI to review a scanned repo. The AI call goes through Cloudflare AI Gateway " +
        "(DLP, caching, rate limiting). AI only sees masked code.",
      {
        scan_id: z.string().describe("Scan ID"),
        question: z.string().default("Review this repo and flag top risks")
          .describe("Question about the scanned repo"),
      },
      async ({ scan_id, question }) => {
        // Step 1: Get all masked files from LocalMask
        const filesResult = await callLocalMask(
          this.env, "GET", `/api/repos/${scan_id}/files`
        ) as { files?: { path: string }[]; error?: string };

        if ("error" in filesResult && filesResult.error) {
          return textResult({ error: filesResult.error });
        }

        const filePaths = (filesResult as { files: { path: string }[] }).files?.map(
          (f: { path: string }) => f.path
        ) || [];

        // Step 2: Fetch masked content for each file
        const parts: string[] = [];
        let totalChars = 0;
        const maxChars = 80_000;

        for (const filePath of filePaths) {
          if (totalChars > maxChars) break;
          const fileData = await callLocalMask(
            this.env, "GET",
            `/api/repos/${scan_id}/files?path=${encodeURIComponent(filePath)}`
          ) as { masked_content?: string };

          if (fileData.masked_content) {
            const chunk = `\n----- FILE: ${filePath} -----\n${fileData.masked_content}`;
            parts.push(chunk);
            totalChars += chunk.length;
          }
        }

        const repoContext = parts.join("");

        // Step 3: Build messages and call AI through AI Gateway
        const messages = [
          {
            role: "user",
            content:
              "I'm sharing a masked repository with you. " +
              "Sensitive values are replaced with tokens like ~[TYPE_N]~. " +
              "Never guess or invent real values behind tokens.\n\n" +
              "MASKED REPOSITORY:\n" + repoContext,
          },
        ];

        // Get acknowledgment first
        const ack = await callAIGateway(this.env, messages);
        if (ack.gateway_blocked) {
          return textResult({
            error: "AI Gateway DLP blocked the request — masked content may still contain sensitive data",
            gateway_blocked: true,
            details: ack.error,
          });
        }
        if (ack.error) {
          return textResult({ error: ack.error });
        }

        messages.push({ role: "assistant", content: ack.answer! });
        messages.push({ role: "user", content: question });

        // Get the actual answer
        const result = await callAIGateway(this.env, messages);
        if (result.gateway_blocked) {
          return textResult({
            error: "AI Gateway DLP blocked the request",
            gateway_blocked: true,
            details: result.error,
          });
        }

        return textResult({
          status: "OK",
          scan_id,
          answer: result.answer,
          routed_through: "Cloudflare AI Gateway",
          dlp_status: "passed",
        });
      }
    );

    // ── test_dlp (demo only — sends unmasked content) ──────────
    this.server.tool(
      "test_dlp",
      "TEST ONLY: Send unmasked content through AI Gateway to verify DLP blocks it. " +
        "This bypasses LocalMask masking to prove the safety net works.",
      {
        content: z.string().default(
          "Review this code:\n" +
          "// Customer payment info (unmasked — should be blocked by DLP)\n" +
          'const CREDIT_CARD = "4242424242424242";\n' +
          'const SSN = "123-45-6789";\n' +
          'const TAX_ID = "912-34-5678";\n' +
          'stripe.charges.create({ amount: 5000, card: "4111111111111111" });\n' +
          "// This content bypasses LocalMask to test AI Gateway's DLP safety net"
        ).describe("Unmasked content to send (contains fake financial data for DLP testing)"),
      },
      async ({ content }) => {
        const messages = [{ role: "user", content }];
        const result = await callAIGateway(this.env, messages);

        if (result.gateway_blocked) {
          return textResult({
            status: "BLOCKED",
            message: "AI Gateway DLP correctly blocked the unmasked content!",
            detail: "This proves the safety net works: if LocalMask's masking " +
                    "ever missed a secret, AI Gateway would catch and block it.",
            dlp_response: result.error,
          });
        }

        return textResult({
          status: "PASSED",
          message: "AI Gateway did NOT block this content. " +
                   "DLP enforcement may require a paid Cloudflare plan (Enterprise / Cloudflare One). " +
                   "Verify DLP policies are active in the AI Gateway dashboard under Firewall.",
          answer: result.answer,
        });
      }
    );

    // ── health ─────────────────────────────────────────────────
    this.server.tool(
      "health",
      "Check connectivity to LocalMask backend and AI Gateway.",
      {},
      async () => {
        const results: Record<string, unknown> = {};

        // Check LocalMask
        try {
          const data = await callLocalMask(this.env, "GET", "/health");
          results.localmask = { status: "ok", backend: data };
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          results.localmask = { status: "error", message: msg };
        }

        // Check AI Gateway (just verify the URL is set)
        results.ai_gateway = {
          url: this.env.AI_GATEWAY_URL ? "configured" : "NOT SET",
          anthropic_key: this.env.ANTHROPIC_API_KEY ? "configured" : "NOT SET",
        };

        return textResult(results);
      }
    );
  }
}

export default LocalMaskGatewayMCP.serve("/mcp");
