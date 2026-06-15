/**
 * Report probe — run on a machine that can reach the QMS server.
 *
 *   node test-report.js [report_key] [YYYY-MM-DD]
 *
 * Logs in, GETs the report page (CStartPage) to scrape the csrf-token, then
 * POSTs the report. Prints what it found at each step. If the csrf-token can't
 * be scraped, it dumps the surrounding HTML so the regex can be tuned.
 *
 * Defaults bake in admin + the known hashPwd; override via env:
 *   QMS_BASE_URL, QMS_USER, QMS_HASH_PWD, QMS_REPORT_PAGE_PATH
 */

process.env.QMS_USER = process.env.QMS_USER || "admin";
process.env.QMS_HASH_PWD =
  process.env.QMS_HASH_PWD ||
  "8dc2fbace07fc965e0030e9ec09df445810bbb73579f4c5c58c106bdf16cc5ee";

const { Session, REPORTS, postReportRaw, condense, today, request, BASE_URL, REPORT_PAGE_PATH } =
  await import("./qms-core.js");

const reportKey = process.argv[2] || "daily_queue_performance";
const date = process.argv[3] || today();
const report = REPORTS[reportKey];
if (!report) {
  console.error("Unknown report:", reportKey, "— available:", Object.keys(REPORTS).join(", "));
  process.exit(1);
}

console.log("Node:", process.version);
console.log(`Report: ${reportKey} (${report.label})  Date: ${date}`);
console.log("Report page:", REPORT_PAGE_PATH, "\n");

try {
  const session = new Session();
  await session.login(); // logs in, then GETs the report page to scrape csrf
  console.log("Login OK. Cookie jar:", session.cookie);
  console.log("csrf-token:", session.csrf || "(EMPTY — scrape failed)");

  // If scrape failed, pull the report page and show where 'csrf' appears so we
  // can fix the regex.
  if (!session.csrf) {
    const page = await request(BASE_URL + REPORT_PAGE_PATH, {
      method: "GET",
      headers: { Cookie: session.cookie },
    });
    const html = page.text || "";
    const idx = html.toLowerCase().indexOf("csrf");
    console.log("\n--- report page csrf context (share this) ---");
    console.log(idx >= 0 ? html.slice(idx - 60, idx + 160) : "(no 'csrf' substring in report page either)");
    console.log("--- end ---\n");
    console.log("Report page length:", html.length, "bytes");
    process.exit(0);
  }

  const r = await postReportRaw(session, report, date);
  console.log("\nReport POST status:", r.status, " Content-Type:", r.ctype, " HTML?", r.looksLikeLogin);
  console.log("--- body preview ---");
  console.log(r.text.slice(0, 400));
  console.log("--- end ---\n");

  if (!r.looksLikeLogin && r.ok) {
    console.log("SUCCESS. Parsed:");
    console.log(JSON.stringify(condense(r.text), null, 2));
  } else {
    console.log("Still HTML after scraping csrf — the token may be per-request, or the");
    console.log("report page needs to be loaded with extra params. Share the preview above.");
  }
} catch (e) {
  console.error("Failed:", e.message);
}
