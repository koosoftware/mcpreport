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
import { REPORTS, fetchReport, today, isIsoDate } from "./qms-core.js";

const server = new McpServer({ name: "qms-report", version: "3.2.0" });

function jsonContent(obj) {
  return { content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] };
}

const reportCatalog = Object.entries(REPORTS)
  .map(([key, r]) => `  - ${key}: ${r.description || r.label}`)
  .join("\n");

server.tool(
  "get_report",
  "Fetch a QMS queue-management report as parsed rows and analyze it to answer the " +
    "user's question. Call this whenever the user asks about queue/branch performance, " +
    "tickets, no-shows, waiting or serving times. The server logs in automatically.\n" +
    "Available reports:\n" +
    reportCatalog +
    "\ndate is YYYY-MM-DD and defaults to today.",
  {
    report: z.string().describe("Report key from the available reports list, e.g. 'daily_queue_performance'."),
    date: z.string().optional().describe("Report date YYYY-MM-DD. Defaults to today."),
  },
  async ({ report, date = "" }) => {
    const def = REPORTS[report];
    if (!def) {
      return jsonContent({ error: "invalid_report", message: `'${report}' is not valid.`, available: Object.keys(REPORTS) });
    }
    if (date && !isIsoDate(date)) {
      return jsonContent({ error: "invalid_date", message: `date must be YYYY-MM-DD, got '${date}'.` });
    }
    try {
      return jsonContent(await fetchReport(def, date || today()));
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
        params: r.params || ["date"],
      })),
      today: today(),
    })
);

const transport = new StdioServerTransport();
await server.connect(transport);
