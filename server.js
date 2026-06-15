/**
 * QMS Reporting MCP Server (test / mock version) — Node.js
 *
 * Exposes a `get_report` tool returning mock Queue Management System data.
 * Use it to validate the end-to-end architecture:
 *
 *   AnythingLLM (host)  ->  Ollama / Qwen  ->  this MCP server  ->  mock data
 *
 * Once the loop works, replace the body of mockData() with a real HTTP call to
 * your QMS backend (see the TODO marker).
 *
 * Transport: stdio (what AnythingLLM spawns by default).
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// Report types the model is allowed to request. Keep this tight so a small
// (8B/9B) model has an unambiguous set to choose from.
const ALLOWED_REPORTS = [
  "daily_ticket_volume",
  "avg_wait_time",
  "counter_performance",
  "service_breakdown",
  "peak_hours",
  "no_show_rate",
];

const today = () => new Date().toISOString().slice(0, 10);

const isIsoDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));

/**
 * Return deterministic mock data per report type.
 *
 * TODO (real version): replace this with an HTTP call, e.g.
 *
 *   const url = new URL(`${process.env.QMS_API_BASE}/reports/${reportType}`);
 *   url.searchParams.set("branch_id", branchId);
 *   url.searchParams.set("from", dateFrom);
 *   url.searchParams.set("to", dateTo);
 *   const resp = await fetch(url, {
 *     headers: { Authorization: `Bearer ${process.env.QMS_API_TOKEN}` },
 *   });
 *   if (!resp.ok) throw new Error(`Backend ${resp.status}`);
 *   return await resp.json();
 */
function mockData(reportType, branchId, dateFrom, dateTo) {
  const branch = branchId || "BR-001";
  const range = { from: dateFrom || today(), to: dateTo || today() };

  switch (reportType) {
    case "daily_ticket_volume":
      return {
        branch_id: branch,
        range,
        unit: "tickets",
        rows: [
          { date: "2026-06-12", issued: 412, served: 398 },
          { date: "2026-06-13", issued: 305, served: 297 },
          { date: "2026-06-14", issued: 128, served: 126 },
        ],
        total_issued: 845,
        total_served: 821,
      };
    case "avg_wait_time":
      return {
        branch_id: branch,
        range,
        unit: "minutes",
        avg_wait_time: 8.7,
        max_wait_time: 34.0,
        by_service: [
          { service: "Account Opening", avg_wait: 12.4 },
          { service: "Cash Deposit", avg_wait: 5.1 },
          { service: "Loan Enquiry", avg_wait: 15.9 },
        ],
      };
    case "counter_performance":
      return {
        branch_id: branch,
        range,
        counters: [
          { counter: "C1", teller: "Aisha", served: 142, avg_service_min: 4.2 },
          { counter: "C2", teller: "Ben", served: 118, avg_service_min: 5.6 },
          { counter: "C3", teller: "Chong", served: 96, avg_service_min: 6.9 },
        ],
      };
    case "service_breakdown":
      return {
        branch_id: branch,
        range,
        unit: "tickets",
        services: [
          { service: "Cash Deposit", count: 310, pct: 36.7 },
          { service: "Withdrawal", count: 221, pct: 26.2 },
          { service: "Account Opening", count: 145, pct: 17.2 },
          { service: "Loan Enquiry", count: 99, pct: 11.7 },
          { service: "Others", count: 70, pct: 8.3 },
        ],
      };
    case "peak_hours":
      return {
        branch_id: branch,
        range,
        unit: "tickets_issued",
        by_hour: [
          { hour: "09:00", count: 78 },
          { hour: "10:00", count: 134 },
          { hour: "11:00", count: 121 },
          { hour: "12:00", count: 95 },
          { hour: "14:00", count: 142 },
          { hour: "15:00", count: 110 },
          { hour: "16:00", count: 65 },
        ],
        peak_hour: "14:00",
      };
    case "no_show_rate":
      return {
        branch_id: branch,
        range,
        called: 845,
        no_shows: 63,
        no_show_rate_pct: 7.5,
      };
    default:
      return { error: `Unhandled report_type: ${reportType}` };
  }
}

const server = new McpServer({ name: "qms-report", version: "1.0.0" });

server.tool(
  "get_report",
  "Fetch a QMS report. report_type must be one of: daily_ticket_volume, avg_wait_time, counter_performance, service_breakdown, peak_hours, no_show_rate. branch_id, date_from (YYYY-MM-DD) and date_to are optional.",
  {
    report_type: z.string().describe("Which report to fetch (see allowed list)."),
    branch_id: z.string().optional().describe('Branch id, e.g. "BR-001". Defaults to BR-001.'),
    date_from: z.string().optional().describe("Start date YYYY-MM-DD. Defaults to today."),
    date_to: z.string().optional().describe("End date YYYY-MM-DD. Defaults to today."),
  },
  async ({ report_type, branch_id = "", date_from = "", date_to = "" }) => {
    // Validate the model's choice before doing any work. Never trust args blindly.
    let result;
    if (!ALLOWED_REPORTS.includes(report_type)) {
      result = {
        error: "invalid_report_type",
        message: `'${report_type}' is not valid.`,
        allowed_report_types: [...ALLOWED_REPORTS].sort(),
      };
    } else if (date_from && !isIsoDate(date_from)) {
      result = { error: "invalid_date", message: `date_from must be YYYY-MM-DD, got '${date_from}'.` };
    } else if (date_to && !isIsoDate(date_to)) {
      result = { error: "invalid_date", message: `date_to must be YYYY-MM-DD, got '${date_to}'.` };
    } else {
      result = mockData(report_type, branch_id, date_from, date_to);
    }
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  }
);

server.tool(
  "list_reports",
  "List the report types this server can return.",
  {},
  async () => ({
    content: [
      {
        type: "text",
        text: JSON.stringify({ report_types: [...ALLOWED_REPORTS].sort(), today: today() }, null, 2),
      },
    ],
  })
);

const transport = new StdioServerTransport();
await server.connect(transport);
