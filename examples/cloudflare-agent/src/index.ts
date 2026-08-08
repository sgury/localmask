/**
 * LocalMask Cloudflare Worker — exposes LocalMask tools as a remote MCP server.
 *
 * Architecture:
 *   MCP Client → this Worker (CF Edge, Streamable HTTP) → LocalMask HTTP API (your machine via cloudflared)
 *
 * The Worker proxies scan/mask/review/publish operations to a LocalMask instance
 * running behind a cloudflared tunnel. Secrets never reach the edge — masking
 * happens on your machine and only masked content crosses the wire.
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

interface Env {
  LOCALMASK_API_URL: string;
  LOCALMASK_API_KEY?: string;
  ALLOW_LOCAL_PATHS?: string; // set to "true" for local dev only
}

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

function textResult(data: unknown): { content: { type: "text"; text: string }[] } {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

export class LocalMaskMCP extends McpAgent<Env> {
  server = new McpServer({
    name: "LocalMask",
    version: "1.0.0",
  });

  async init() {
    // ── scan_repo ──────────────────────────────────────────────
    this.server.tool(
      "scan_repo",
      "Scan a repository for secrets, credentials, and sensitive data. " +
        "Pass a git URL (or local path if ALLOW_LOCAL_PATHS is enabled). " +
        "Returns a scan_id for subsequent operations.",
      {
        source: z.string().describe("Git URL to scan (e.g. https://github.com/org/repo)"),
        sensitivity: z
          .enum(["minimal", "standard", "strict"])
          .default("standard")
          .describe("Detection sensitivity level"),
      },
      async ({ source, sensitivity }) => {
        // Security: block local paths unless explicitly allowed.
        // Without this, remote users could read arbitrary files on the server.
        const isLocalPath = !source.startsWith("http://") &&
                            !source.startsWith("https://") &&
                            !source.startsWith("git@");
        if (isLocalPath && this.env.ALLOW_LOCAL_PATHS !== "true") {
          return textResult({
            error: "Local paths are disabled for security. Use a git URL, " +
                   "or set ALLOW_LOCAL_PATHS=true in wrangler.toml for local dev.",
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
      "Get all detections from a scan — types, counts, confidence scores, and review status.",
      {
        scan_id: z.string().describe("Scan ID from scan_repo"),
      },
      async ({ scan_id }) => {
        const data = await callLocalMask(
          this.env,
          "GET",
          `/api/repos/${scan_id}/detections`
        );
        return textResult(data);
      }
    );

    // ── get_file_masked ────────────────────────────────────────
    this.server.tool(
      "get_file_masked",
      "Read a specific file from a scan with all secrets replaced by ~[TOKEN]~ placeholders. " +
        "Omit path to list all files in the scan.",
      {
        scan_id: z.string().describe("Scan ID"),
        path: z
          .string()
          .optional()
          .describe("Relative file path (omit to list files)"),
      },
      async ({ scan_id, path }) => {
        const query = path ? `?path=${encodeURIComponent(path)}` : "";
        const data = await callLocalMask(
          this.env,
          "GET",
          `/api/repos/${scan_id}/files${query}`
        );
        return textResult(data);
      }
    );

    // ── review_detection ───────────────────────────────────────
    this.server.tool(
      "review_detection",
      "Approve or reject detections. Pass a map of detection IDs to decisions.",
      {
        scan_id: z.string().describe("Scan ID"),
        decisions: z
          .record(z.enum(["approved", "rejected"]))
          .describe('Map of det_id → "approved" or "rejected"'),
      },
      async ({ scan_id, decisions }) => {
        const data = await callLocalMask(
          this.env,
          "POST",
          `/api/repos/${scan_id}/review`,
          { decisions }
        );
        return textResult(data);
      }
    );

    // ── publish_masked_repo ────────────────────────────────────
    this.server.tool(
      "publish_masked_repo",
      "Push the masked copy of a scanned repo to a git remote. " +
        "All secrets are replaced with ~[TOKEN]~ placeholders.",
      {
        scan_id: z.string().describe("Scan ID"),
        target_url: z
          .string()
          .describe("Git remote URL to push the masked repo to"),
      },
      async ({ scan_id, target_url }) => {
        const data = await callLocalMask(
          this.env,
          "POST",
          `/api/repos/${scan_id}/publish`,
          { target_url }
        );
        return textResult(data);
      }
    );

    // ── ask_about_scan ────────────────────────────────────────
    this.server.tool(
      "ask_about_scan",
      "Ask AI to analyze a scanned repository. The AI only sees masked content — " +
        "great for security reviews, code quality, and risk assessment.",
      {
        scan_id: z.string().describe("Scan ID"),
        question: z
          .string()
          .default("Review this repo and flag top risks")
          .describe("Question to ask about the scanned repo"),
        provider: z
          .enum(["anthropic", "openai", "gemini"])
          .default("anthropic")
          .describe("AI provider to use"),
      },
      async ({ scan_id, question, provider }) => {
        const data = await callLocalMask(
          this.env,
          "POST",
          `/api/repos/${scan_id}/ask`,
          { question, provider }
        );
        return textResult(data);
      }
    );

    // ── health ─────────────────────────────────────────────────
    this.server.tool(
      "health",
      "Check if the LocalMask backend is reachable.",
      {},
      async () => {
        try {
          const data = await callLocalMask(this.env, "GET", "/health");
          return textResult({ status: "ok", backend: data });
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          return textResult({
            status: "error",
            message: `LocalMask backend not reachable — is cloudflared running? ${msg}`,
          });
        }
      }
    );
  }
}

export default LocalMaskMCP.serve("/mcp");
