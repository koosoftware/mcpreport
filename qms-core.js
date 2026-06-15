/**
 * QMS core — shared logic for the MCP server and the test scripts.
 *
 * Handles: portable HTTP, auto-login + full cookie jar, csrf-token scraping,
 * the report payload template, the report POST, and CSV parsing.
 *
 * Config via env (set once, stable):
 *   QMS_BASE_URL   default http://54.251.164.99:49999
 *   QMS_USER       login user id
 *   QMS_HASH_PWD   hashPwd value from the login payload (stable hash)
 *     -- or --
 *   QMS_PASS       plaintext password; SHA-256'd into hashPwd
 *   QMS_REPORT_PAGE_PATH  (optional) a path to GET after login to scrape the
 *                  csrf-token, if the report endpoint requires it.
 */

import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import { createHash } from "node:crypto";

export const BASE_URL = process.env.QMS_BASE_URL || "http://54.251.164.99:49999";
const USER = process.env.QMS_USER || "";
const HASH_PWD =
  process.env.QMS_HASH_PWD ||
  (process.env.QMS_PASS ? createHash("sha256").update(process.env.QMS_PASS).digest("hex") : "");
export const REPORT_PAGE_PATH =
  process.env.QMS_REPORT_PAGE_PATH ||
  "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CStartPage";

const LOGIN_PATH = "/QMS700i/servlet/my.com.gms.qms.mnt.servlets.CSignOn?param=SUBMIT";
export const REPORT_PATH = "/QMS700i/servlet/my.com.gms.qms.rpt.servlets.CGenerateReport";
const MAX_ROWS = 200;

// Report registry. Each entry: a friendly key, a human label, a `description`
// (used by the model to decide when the report is relevant), the input `params`,
// and the servlet identifiers. The hLoad1stRec* fields are captured UI state and
// are sent verbatim — they don't change which report is generated (hRptId does).
export const REPORTS = {
  daily_queue_performance: {
    label: "Daily Queue Performance By Day",
    description:
      "Per-day queue performance metrics for a given date: tickets issued, no-shows, " +
      "tickets served, transfers, total; and average / longest / total waiting time, " +
      "serving time and time spent (HH:MM:SS). One row per day. Use for questions about " +
      "daily queue/branch performance, ticket volume, no-shows, wait times or serving times.",
    params: ["date"],
    hRptId: "11028",
    hRptType: "D",
    hRptClassId: "1",
    hLoad1stRecId: "99023134",
    hLoad1stRecNm: "AKPK Appointment Ticket Report",
  },
};

const PAYLOAD_TEMPLATE =
  "csrf-token=&useExpDt=on&useExpDt2=on&rptDt=&rptYr=&rptYearly=&TimeFormatOpt=1" +
  "&selTgtAvgWt=&selTgtAvgSt=&selWTRange=&selTrxSTRange=&selTgtWt2=&selTgtSt2=" +
  "&selTgtTt2=&selTgtTrxSt2=&chkAllBrhGrp=on&chkAllBrh=on&chkAllTrxGrp=on" +
  "&chkAllSrvGrpTyp=on&chkAllSvcGrp=on&chkAllSvc=on&chkAllCnt=on&chkAllTr=on" +
  "&chkAllTrans=on&chkAllTod=on&chkAllWt=on&chkAllSt=on&chkAllTrxSt=on" +
  "&chkAllQuesGrp=on&chkAllQues=on&chkAllAns=on&chkAllIct=on&hiddenBrhGrpTyp=" +
  "&hiddenSvcGrpTyp=&hiddenTrxGrpTyp=&hRptClassId=1&hRptSelBrhCode=&hRptIsCorp=false" +
  "&hRptType=D&hRptId=11028&hRptDataIn=3&hRptOut=csv&hSelBrh=&hSelMth=&hSelServ=" +
  "&hSelCounter=&hSelTeller=&hSelDayTimeSlot=&hSelWTItv=&hSelSTItv=&hSelRptWTItvGrp=" +
  "&hSelRptSTItvGrp=&hSelRptTrsSTItvGrp=&hSelTgtWt=&hSelTgtSt=&hSelTgtTt=&hSelQuestion=" +
  "&hSelAnswer=&hSelTransaction=&hSelBrhGrp=&hSelSvcGrp=&hSelServPrio=&hSelTgtAvgWt=" +
  "&hSelTgtAvgSt=&hSelTmFmt=1&hSelQuesGrp=&hSelBrhGrpType=&hSelTrxSTItv=&hSelTgtTrxSt=" +
  "&hSelTrxSTRange=&hSelWTRange=&hSelIct=&hSelTrxGrpTyp=&hSelTrxGrp=&hSelTmPeriod=" +
  "&hSelStartWorkTm=&hSelSvcGrpTyp=&hLoad1stRecFlg=Y&hLoad1stRecId=99023134" +
  "&hLoad1stRecNm=AKPK+Appointment+Ticket+Report&hLoad1stRecTyp=P&hApplyExpDate=Y" +
  "&hSelectAllServiceFlg=N&hSelectAllBranchFlg=N&hSelectAllTellerFlg=N" +
  "&hSelectAllTrxFlg=N&rptLevel=1&rptSelFieldIdList=0&hServTypeSelInd=0" +
  "&hBrhTypeSelInd=0&hTgtWtTypeSelInd=0&hTgtStTypeSelInd=0&hTgtTrxStTypeSelInd=0" +
  "&hTgtTtTypeSelInd=0&hIctTypeSelInd=0&hTellerTypeSelInd=0&hSvcGrpSelectionType=0" +
  "&hBrhGrpSelectionType=0&hQuesGrpSelectionType=0&hSvcGrpTypSelectionType=0" +
  "&hTmFmtSelInd=Y&hMthSelInd=N&hServSelInd=N&hBrhInd=N&hCounterSelInd=N" +
  "&hTellerSelInd=N&hDayTimeSlotSelInd=N&hWTItvSelInd=N&hSTItvSelInd=N" +
  "&hQuestionSelInd=N&hAnswerSelInd=N&hTransactionSelInd=N&hBrhGrpSelInd=N" +
  "&hSvcGrpSelInd=N&hServPrioSelInd=N&hTgtAvgWtSelInd=N&hTgtAvgStSelInd=N" +
  "&hQuesGrpSelInd=N&hBrhGrpTypeSelInd=N&hTrxSTItvSelInd=N&hTrxSTRangeSelInd=N" +
  "&hWTRangeSelInd=N&hIctSelInd=N&hTrxGrpTypeSelInd=N&hTrxGrpSelInd=N" +
  "&hTmPeriodSelInd=N&hStartWorkTmInd=N&hSelSvcGrpTypInd=N&hBranchGrpSelPurpose=0" +
  "&hServiceGrpSelPurpose=1&hTrxGrpSelPurpose=0&hWtGrpIsUpdate=Y&hStGrpIsUpdate=Y" +
  "&hTrsStGrpIsUpdate=Y&hUploadFolderNm=&hIsDefRpt=Y&hIsUsrRpt=N&hSelStdWt=" +
  "&hSelStdWtP2=&hSelStdSt=&hSelStdStP2=";

export const today = () => new Date().toISOString().slice(0, 10);
export const isIsoDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s));

/** Portable HTTP request (built-in http/https — no global fetch dependency). */
export function request(urlStr, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlStr);
    const lib = u.protocol === "https:" ? https : http;
    const data = body ? Buffer.from(body) : null;
    const opts = {
      method,
      hostname: u.hostname,
      port: u.port || (u.protocol === "https:" ? 443 : 80),
      path: u.pathname + u.search,
      headers: { ...headers, ...(data ? { "Content-Length": data.length } : {}) },
    };
    const req = lib.request(opts, (res) => {
      let chunks = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (chunks += c));
      res.on("end", () =>
        resolve({
          status: res.statusCode,
          headers: res.headers,
          setCookies: res.headers["set-cookie"] || [],
          text: chunks,
        })
      );
    });
    req.on("error", reject);
    req.setTimeout(30000, () => req.destroy(new Error("request timeout")));
    if (data) req.write(data);
    req.end();
  });
}

/** Merge Set-Cookie headers into a single Cookie header, keeping ALL cookies.
 *  Applies in order; later non-empty values overwrite earlier ones. */
export function buildCookieHeader(setCookies) {
  const jar = {};
  for (const sc of setCookies) {
    const pair = sc.split(";")[0];
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (!name) continue;
    if (value) jar[name] = value; // ignore empty (clear) values; keep last real one
  }
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");
}

export function scrapeCsrf(html) {
  const patterns = [
    /name=["']csrf-token["'][^>]*value=["']([^"']+)["']/i,
    /value=["']([^"']+)["'][^>]*name=["']csrf-token["']/i,
    /<meta[^>]*name=["']csrf-token["'][^>]*content=["']([^"']+)["']/i,
    /["']?csrf-token["']?\s*[:=]\s*["']([A-Za-z0-9]{20,})["']/i,
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m) return m[1];
  }
  return "";
}

export class Session {
  constructor() {
    this.cookie = "";
    this.csrf = "";
  }

  get isValid() {
    return Boolean(this.cookie);
  }

  async login() {
    if (!USER || !HASH_PWD) {
      throw new Error("QMS_USER and QMS_HASH_PWD (or QMS_PASS) env vars are required.");
    }
    const body = new URLSearchParams({
      txtUsrId: USER,
      txtPwd: "",
      hashPwd: HASH_PWD,
      randomNum: "0",
      mod: "",
      urlRedirect: "",
    }).toString();
    const resp = await request(BASE_URL + LOGIN_PATH, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    this.cookie = buildCookieHeader(resp.setCookies);
    if (!this.cookie) {
      throw new Error("login failed: no session cookie (check QMS_USER / QMS_HASH_PWD).");
    }
    // csrf-token may be in the login response, or on a separate report page.
    this.csrf = scrapeCsrf(resp.text || "");
    if (!this.csrf && REPORT_PAGE_PATH) {
      const page = await request(BASE_URL + REPORT_PAGE_PATH, {
        method: "GET",
        headers: { Cookie: this.cookie },
      });
      this.csrf = scrapeCsrf(page.text || "");
    }
    return this;
  }

  async ensure() {
    if (!this.isValid) await this.login();
    return this;
  }
}

export function buildBody(report, rptDt, csrf) {
  const p = new URLSearchParams(PAYLOAD_TEMPLATE);
  p.set("csrf-token", csrf || "");
  p.set("rptDt", rptDt);
  p.set("hRptOut", "csv");
  p.set("hRptId", report.hRptId);
  p.set("hRptType", report.hRptType);
  p.set("hRptClassId", report.hRptClassId);
  p.set("hLoad1stRecId", report.hLoad1stRecId);
  p.set("hLoad1stRecNm", report.hLoad1stRecNm);
  return p.toString();
}

/** Low-level report POST. Returns the raw response details. */
export async function postReportRaw(session, report, rptDt) {
  const resp = await request(BASE_URL + REPORT_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: session.cookie },
    body: buildBody(report, rptDt, session.csrf),
  });
  const ctype = (resp.headers["content-type"] || "").toLowerCase();
  const text = resp.text;
  const isRedirect = resp.status >= 300 && resp.status < 400;
  const looksLikeLogin = isRedirect || ctype.includes("text/html") || text.trimStart().startsWith("<");
  const ok = resp.status >= 200 && resp.status < 400;
  return { ok, status: resp.status, ctype, text, looksLikeLogin };
}

// Module-level session reused across MCP calls.
const session = new Session();

/** High-level: ensure login, fetch + parse the report, retry once on expiry. */
export async function fetchReport(report, rptDt) {
  await session.ensure();
  let r = await postReportRaw(session, report, rptDt);
  if (r.looksLikeLogin) {
    session.cookie = "";
    await session.login();
    r = await postReportRaw(session, report, rptDt);
  }
  if (!r.ok) return { error: "http_error", status: r.status, body_preview: r.text.slice(0, 300) };
  if (r.looksLikeLogin) {
    return { error: "session_expired", message: "Got HTML after re-login — csrf may be required or params invalid." };
  }
  return { report: report.label, date: rptDt, ...condense(r.text) };
}

export function parseCSV(text) {
  const rows = [];
  let field = "";
  let row = [];
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; }
        else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
    else if (c !== "\r") field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((c) => c !== ""));
}

export function condense(csvText) {
  const rows = parseCSV(csvText);
  if (rows.length === 0) return { columns: [], row_count: 0, rows: [] };
  const columns = rows[0];
  const dataRows = rows.slice(1);
  const capped = dataRows.slice(0, MAX_ROWS).map((r) => {
    const obj = {};
    columns.forEach((col, idx) => { obj[col || `col${idx}`] = r[idx] ?? ""; });
    return obj;
  });
  return {
    columns,
    row_count: dataRows.length,
    returned: capped.length,
    truncated: dataRows.length > MAX_ROWS,
    rows: capped,
  };
}
