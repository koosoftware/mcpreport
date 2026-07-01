/**
 * QMS Reporting MCP Server — auto-login + real CSV fetch from QMS700i.
 *
 *   AnythingLLM (host)  ->  Ollama / Qwen  ->  this MCP server  ->  QMS servlet (CSV)
 *
 * The server authenticates itself (see qms-core.js). You only set credentials
 * via the AnythingLLM `env` block: QMS_USER + QMS_HASH_PWD (and optionally
 * QMS_BASE_URL, QMS_REPORT_PAGE_PATH). No cookies/tokens to manage.
 *
 * Transport: stdio.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import {
  REPORTS,
  fetchReport,
  searchReports,
  inputFor,
  today,
  thisMonth,
  isIsoDate,
  isYearMonth,
  parseCounters,
  DEFAULT_COUNTERS,
  sessionForWorkspace,
} from "./qms-core.js";

const server = new McpServer({ name: "qms-report", version: "4.0.0" });

function jsonContent(obj) {
  return { content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] };
}

// --- Two-stage routing -------------------------------------------------------
// With 130+ reports, embedding the whole catalog in get_report's description
// overwhelmed small models (the schema alone was ~12k tokens). Instead the model
// first calls find_reports with the user's plain-language need to get a short
// shortlist of matching report keys, then calls get_report with the chosen key.

server.tool(
  "find_reports",
  "STEP 1 — find the right report. Given the user's plain-language question about " +
    "queue/branch performance, tickets, waiting/serving times, counters, tellers, or " +
    "customer ratings/feedback, return a short shortlist of matching QMS report keys " +
    "with the input each one needs. Call this FIRST whenever you are not 100% sure of " +
    "the exact report key, then call get_report with the best match. Example queries: " +
    "'monthly customer rating by teller', 'daily idle log', 'queue performance by service'.",
  {
    query: z.string().describe("The user's need in plain language, e.g. 'monthly rating by teller'."),
    limit: z.number().int().optional().describe("How many matches to return (default 6)."),
  },
  async ({ query, limit }) => {
    const matches = searchReports(query, limit || 6);
    if (!matches.length) {
      return jsonContent({
        matches: [],
        message:
          "No report matched. Try simpler keywords (e.g. 'queue performance', 'rating by teller', " +
          "'idle log'), or call list_reports to browse all available report keys.",
      });
    }
    return jsonContent({
      matches: matches.map(({ key, label, input, description }) => ({ key, label, input, description })),
      next: "Pick the best `key` and call get_report with it (plus period/date_from/date_to).",
    });
  }
);

server.tool(
  "get_report",
  "STEP 2 — fetch a report. Fetch a QMS report as parsed rows and analyze it to answer " +
    "the user's question. Pass the exact `report` key (use find_reports first if unsure). " +
    "Daily reports: pass `period` as YYYY-MM-DD. Monthly reports: `period` as YYYY-MM. " +
    "Range/periodic reports: pass `date_from` and `date_to`. Defaults to current day/month. " +
    "The server logs in automatically.",
  {
    report: z.string().describe("Exact report key (from find_reports), e.g. 'monthly_customer_rating_by_teller'."),
    period: z
      .string()
      .optional()
      .describe("For daily reports: YYYY-MM-DD. For monthly reports: YYYY-MM. Defaults to current day/month. Not used for range reports."),
    date_from: z.string().optional().describe("Range reports only: start date YYYY-MM-DD."),
    date_to: z.string().optional().describe("Range reports only: end date YYYY-MM-DD."),
    counters: z
      .string()
      .optional()
      .describe("Per-counter reports only: which counter number(s), e.g. '1,3,5' or a range '1-15'. Required for by-counter reports unless an install default is configured."),
    workspace_slug: z
      .string()
      .describe(
        "Internal: identifies which QMS install/branch to query. This is injected " +
          "automatically by the AnythingLLM host on every call — do not ask the user " +
          "for it and do not attempt to set it yourself."
      ),
  },
  async ({ report, period = "", date_from = "", date_to = "", counters = "", workspace_slug }) => {
    const def = REPORTS[report];
    if (!def) {
      // Don't dump all keys (there are 130+). Suggest the closest matches instead.
      return jsonContent({
        error: "invalid_report",
        message: `'${report}' is not a valid report key. Call find_reports with the user's question to get valid keys.`,
        suggestions: searchReports(report, 6).map((m) => m.key),
      });
    }

    // Resolve which QMS install this workspace targets before doing anything else.
    let session;
    try {
      session = sessionForWorkspace(workspace_slug);
    } catch (e) {
      return jsonContent({ error: "unknown_workspace", message: String(e?.message || e) });
    }

    // Per-counter reports need an explicit counter list (no select-all). If none is
    // given and no install default exists, ask the user which counters to include.
    let counterIds = null;
    if (def.counters) {
      counterIds = counters ? parseCounters(counters) : [];
      if (!counterIds.length) counterIds = DEFAULT_COUNTERS;
      if (!counterIds.length) {
        return jsonContent({
          error: "counters_required",
          message:
            "This is a per-counter report. Please ask the user which counter number(s) to " +
            "include (e.g. '1,3,5' or a range like '1-15'), then call get_report again with " +
            "the `counters` argument.",
        });
      }
    }

    try {
      let args;
      if (def.period === "range") {
        const from = date_from || today();
        const to = date_to || date_from || today();
        if (!isIsoDate(from)) return jsonContent({ error: "invalid_period", message: `date_from must be YYYY-MM-DD, got '${from}'.` });
        if (!isIsoDate(to)) return jsonContent({ error: "invalid_period", message: `date_to must be YYYY-MM-DD, got '${to}'.` });
        args = { from, to };
      } else {
        const monthly = def.period === "monthly";
        const value = period || (monthly ? thisMonth() : today());
        if (monthly && !isYearMonth(value)) {
          return jsonContent({ error: "invalid_period", message: `monthly report needs period as YYYY-MM, got '${value}'.` });
        }
        if (!monthly && !isIsoDate(value)) {
          return jsonContent({ error: "invalid_period", message: `daily report needs period as YYYY-MM-DD, got '${value}'.` });
        }
        args = { period: value };
      }
      if (counterIds) args.counters = counterIds;
      return jsonContent(await fetchReport(def, args, session));
    } catch (e) {
      return jsonContent({ error: "request_failed", message: String(e?.message || e) });
    }
  }
);

server.tool(
  "list_reports",
  "List the report keys this server can fetch.",
  {},
  async () =>
    jsonContent({
      reports: Object.entries(REPORTS).map(([key, r]) => ({
        key,
        label: r.label,
        description: r.description || "",
        input: inputFor(r),
      })),
      today: today(),
    })
);

const transport = new StdioServerTransport();
await server.connect(transport);
