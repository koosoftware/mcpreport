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
import { REPORTS, fetchReport, today, thisMonth, isIsoDate, isYearMonth } from "./qms-core.js";

const server = new McpServer({ name: "qms-report", version: "3.2.0" });

function jsonContent(obj) {
  return { content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] };
}

const inputFor = (r) =>
  r.period === "monthly"
    ? "month YYYY-MM"
    : r.period === "range"
    ? "date_from + date_to (YYYY-MM-DD)"
    : "date YYYY-MM-DD";

const reportCatalog = Object.entries(REPORTS)
  .map(([key, r]) => `  - ${key} (input: ${inputFor(r)}): ${r.description || r.label}`)
  .join("\n");

server.tool(
  "get_report",
  "Fetch a QMS queue-management report as parsed rows and analyze it to answer the " +
    "user's question. Call this whenever the user asks about queue/branch performance, " +
    "tickets, no-shows, waiting or serving times. The server logs in automatically.\n" +
    "Available reports:\n" +
    reportCatalog +
    "\nDaily/monthly reports: pass `period`. Range reports: pass `date_from` and " +
    "`date_to`. Defaults to the current day/month.",
  {
    report: z.string().describe("Report key from the available reports list, e.g. 'daily_queue_performance'."),
    period: z
      .string()
      .optional()
      .describe("For daily reports: YYYY-MM-DD. For monthly reports: YYYY-MM. Defaults to current day/month. Not used for range reports."),
    date_from: z.string().optional().describe("Range reports only: start date YYYY-MM-DD."),
    date_to: z.string().optional().describe("Range reports only: end date YYYY-MM-DD."),
  },
  async ({ report, period = "", date_from = "", date_to = "" }) => {
    const def = REPORTS[report];
    if (!def) {
      return jsonContent({ error: "invalid_report", message: `'${report}' is not valid.`, available: Object.keys(REPORTS) });
    }
    try {
      if (def.period === "range") {
        const from = date_from || today();
        const to = date_to || date_from || today();
        if (!isIsoDate(from)) return jsonContent({ error: "invalid_period", message: `date_from must be YYYY-MM-DD, got '${from}'.` });
        if (!isIsoDate(to)) return jsonContent({ error: "invalid_period", message: `date_to must be YYYY-MM-DD, got '${to}'.` });
        return jsonContent(await fetchReport(def, { from, to }));
      }
      const monthly = def.period === "monthly";
      const value = period || (monthly ? thisMonth() : today());
      if (monthly && !isYearMonth(value)) {
        return jsonContent({ error: "invalid_period", message: `monthly report needs period as YYYY-MM, got '${value}'.` });
      }
      if (!monthly && !isIsoDate(value)) {
        return jsonContent({ error: "invalid_period", message: `daily report needs period as YYYY-MM-DD, got '${value}'.` });
      }
      return jsonContent(await fetchReport(def, { period: value }));
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
