/**
 * LocalMask Remote MCP Server — full tool surface on Cloudflare Workers.
 *
 * Exposes all LocalMask scanning, masking, review, and publishing tools as a
 * remote MCP server over Streamable HTTP. Any MCP client can connect without
 * installing LocalMask locally.
 *
 * Architecture:
 *   MCP Client → this Worker (Streamable HTTP) → LocalMask HTTP API (hosted backend)
 *
 * The Worker is stateless — all state lives in the LocalMask backend.
 * Auth: Bearer token checked on every MCP request (MCP_AUTH_TOKEN secret).
 */

import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

// ── Types ──────────────────────────────────────────────────────────────────

interface Env {
  LOCALMASK_API_URL: string;
  LOCALMASK_API_KEY?: string;
  MCP_AUTH_TOKEN?: string;
  MCP_OBJECT: DurableObjectNamespace;
}

// ── Backend client ─────────────────────────────────────────────────────────

async function api(
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
    const text = await res.text();
    throw new Error(`LocalMask ${res.status} on ${method} ${path}: ${text}`);
  }
  return res.json();
}

function text(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function err(message: string) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify({ error: message }) }],
    isError: true as const,
  };
}

// ── MCP Server ─────────────────────────────────────────────────────────────

export class LocalMaskRemoteMCP extends McpAgent<Env> {
  server = new McpServer({
    name: "LocalMask",
    version: "1.0.0",
  });

  async init() {
    // ── Scanning ───────────────────────────────────────────────

    this.server.tool(
      "scan_repo",
      "Scan a repository for secrets, credentials, and sensitive data. " +
        "Pass a git URL or a path on the backend machine. Returns a scan_id.",
      {
        source: z.string().describe("Git URL or local path to scan"),
        sensitivity: z
          .enum(["minimal", "standard", "strict"])
          .default("standard")
          .describe("Detection sensitivity: minimal (low FP), standard, strict (high recall)"),
        org: z
          .string()
          .default("default")
          .describe("Organization namespace"),
      },
      async ({ source, sensitivity, org }) => {
        const data = await api(this.env, "POST", "/api/repos/scan", {
          repo_url: source,
          sensitivity,
          org,
        });
        return text(data);
      }
    );

    this.server.tool(
      "sync_repo",
      "Re-scan a previously scanned repo after git updates. Pulls latest code and re-runs detection.",
      {
        scan_id: z.string().describe("Scan ID to re-sync"),
      },
      async ({ scan_id }) => {
        // Use the scan endpoint with the existing scan's repo URL
        const scan = (await api(this.env, "GET", `/api/repos/${scan_id}`)) as Record<string, unknown>;
        const data = await api(this.env, "POST", "/api/repos/scan", {
          repo_url: scan.repo_url,
          sensitivity: scan.sensitivity || "standard",
          org: scan.org || "default",
        });
        return text(data);
      }
    );

    // ── Detections & Review ────────────────────────────────────

    this.server.tool(
      "get_detections",
      "Get all detections from a scan — types, counts, confidence scores, and review status.",
      {
        scan_id: z.string().describe("Scan ID"),
      },
      async ({ scan_id }) => {
        const data = await api(this.env, "GET", `/api/repos/${scan_id}/detections`);
        return text(data);
      }
    );

    this.server.tool(
      "get_review_queue",
      "Get review progress — how many detections are pending, approved, or rejected.",
      {
        scan_id: z.string().describe("Scan ID"),
      },
      async ({ scan_id }) => {
        const data = await api(this.env, "GET", `/api/repos/${scan_id}`);
        return text(data);
      }
    );

    this.server.tool(
      "review_detection",
      "Approve or reject a single detection.",
      {
        scan_id: z.string().describe("Scan ID"),
        det_id: z.string().describe("Detection ID to review"),
        decision: z.enum(["approved", "rejected"]).describe("Approve or reject"),
      },
      async ({ scan_id, det_id, decision }) => {
        const data = await api(this.env, "POST", `/api/repos/${scan_id}/review`, {
          decisions: { [det_id]: decision },
        });
        return text(data);
      }
    );

    this.server.tool(
      "bulk_review",
      "Approve or reject multiple detections at once.",
      {
        scan_id: z.string().describe("Scan ID"),
        decisions: z
          .record(z.enum(["approved", "rejected"]))
          .describe('Map of det_id → "approved" or "rejected"'),
      },
      async ({ scan_id, decisions }) => {
        const data = await api(this.env, "POST", `/api/repos/${scan_id}/review`, {
          decisions,
        });
        return text(data);
      }
    );

    // ── Masked file access ─────────────────────────────────────

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
        const data = await api(
          this.env,
          "GET",
          `/api/repos/${scan_id}/files${query}`
        );
        return text(data);
      }
    );

    // ── Approval workflow ──────────────────────────────────────

    this.server.tool(
      "submit_for_review",
      "Submit a scan for security team approval. Moves status from draft to submitted.",
      {
        scan_id: z.string().describe("Scan ID"),
      },
      async ({ scan_id }) => {
        const data = await api(this.env, "POST", `/api/repos/${scan_id}/submit`, {});
        return text(data);
      }
    );

    this.server.tool(
      "approve_scan",
      "Security manager approves the scan. Moves status to approved.",
      {
        scan_id: z.string().describe("Scan ID"),
        reviewer: z.string().default("mcp_user").describe("Reviewer name"),
      },
      async ({ scan_id, reviewer }) => {
        const data = await api(this.env, "POST", `/api/repos/${scan_id}/approve`, {
          reviewed_by: reviewer,
        });
        return text(data);
      }
    );

    // ── Publishing ─────────────────────────────────────────────

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
        const data = await api(this.env, "POST", `/api/repos/${scan_id}/publish`, {
          target_url,
        });
        return text(data);
      }
    );

    // ── AI Analysis ────────────────────────────────────────────

    this.server.tool(
      "ask_about_scan",
      "Ask AI to analyze a scanned repository. The AI only sees masked content. " +
        "Great for security reviews, risk assessment, and code analysis.",
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
        const data = await api(this.env, "POST", `/api/repos/${scan_id}/ask`, {
          question,
          provider,
        });
        return text(data);
      }
    );

    // ── Model Learning ─────────────────────────────────────────

    this.server.tool(
      "get_model_stats",
      "Get statistics about the detection model — learned rules, accuracy, training status.",
      {},
      async () => {
        const data = await api(this.env, "GET", "/api/model/stats");
        return text(data);
      }
    );

    this.server.tool(
      "retrain_model",
      "Trigger a retrain cycle on accumulated reviewer feedback. The model learns from approved/rejected decisions.",
      {},
      async () => {
        const data = await api(this.env, "POST", "/api/model/retrain", {});
        return text(data);
      }
    );

    // ── Utility ────────────────────────────────────────────────

    this.server.tool(
      "health",
      "Check if the LocalMask backend is reachable and healthy.",
      {},
      async () => {
        try {
          const data = await api(this.env, "GET", "/health");
          return text({ status: "ok", backend: data });
        } catch (e: unknown) {
          const msg = e instanceof Error ? e.message : String(e);
          return err(`Backend unreachable: ${msg}`);
        }
      }
    );

    this.server.tool(
      "list_scans",
      "List all scans on the backend.",
      {},
      async () => {
        const data = await api(this.env, "GET", "/api/repos");
        return text(data);
      }
    );
  }
}

// ── Auth middleware + serve ─────────────────────────────────────────────────

const mcpHandler = LocalMaskRemoteMCP.serve("/mcp");

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    // Allow health checks without auth
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        headers: { "Content-Type": "application/json" },
      });
    }

    // Bearer token auth for MCP endpoints
    if (env.MCP_AUTH_TOKEN) {
      const auth = request.headers.get("Authorization");
      if (!auth || auth !== `Bearer ${env.MCP_AUTH_TOKEN}`) {
        return new Response(
          JSON.stringify({
            jsonrpc: "2.0",
            error: { code: -32000, message: "Unauthorized" },
            id: null,
          }),
          { status: 401, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    return mcpHandler.fetch(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
