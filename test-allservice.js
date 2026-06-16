/**
 * Probe: does the by-service report return ALL services when we rely only on the
 * select-all flag, without hardcoding the install-specific service IDs?
 *
 *   node test-allservice.js [YYYY-MM-DD]
 *
 * Logs in, then POSTs report 11095 twice and compares:
 *   A) "select all" — hSelServ emptied and the individual service checkbox fields
 *      removed; relies on hSelectAllServiceFlg=Y + chkAllSvc=on.
 *   B) "control"    — the captured payload as-is (hSelServ=1,2,3,4,5).
 *
 * If A returns the same (or more) data rows as B, we can drop the hardcoded IDs.
 *
 * Defaults bake in admin + the known hashPwd; override via env:
 *   QMS_BASE_URL, QMS_USER, QMS_HASH_PWD
 */

process.env.QMS_USER = process.env.QMS_USER || "admin";
process.env.QMS_HASH_PWD =
  process.env.QMS_HASH_PWD ||
  "8dc2fbace07fc965e0030e9ec09df445810bbb73579f4c5c58c106bdf16cc5ee";

const { Session, REPORTS, request, BASE_URL, REPORT_PATH, condense } = await import("./qms-core.js");

const date = process.argv[2] || new Date().toISOString().slice(0, 10);
const report = REPORTS.daily_by_service_queue_performance;

// The install-specific service checkbox field names from the captured payload.
const SERVICE_FIELDS = [
  "Self Service Terminal",
  "With Appointment Advisory",
  "With Appointment - Post DMP / Less 3 facilities",
  "Without Appointment - Advisory",
  "Without Appointment - Post DMP / Less 3 facilities",
];

function buildVariant(csrf, selectAllOnly) {
  const p = new URLSearchParams(report.payload);
  p.set("csrf-token", csrf || "");
  p.set("hRptOut", "csv");
  p.set("rptDt", date);
  if (selectAllOnly) {
    for (const f of SERVICE_FIELDS) p.delete(f); // drop hardcoded service checkboxes
    p.set("hSelServ", ""); // no explicit IDs — rely on the select-all flag
  }
  return p.toString();
}

async function post(body) {
  const resp = await request(BASE_URL + REPORT_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: session.cookie },
    body,
  });
  const ctype = (resp.headers["content-type"] || "").toLowerCase();
  const isHtml = ctype.includes("text/html") || resp.text.trimStart().startsWith("<");
  return { status: resp.status, ctype, isHtml, text: resp.text };
}

function summarize(label, r) {
  console.log(`\n=== ${label} ===`);
  console.log("status:", r.status, " content-type:", r.ctype, " HTML?", r.isHtml);
  if (r.isHtml) {
    console.log("-> got HTML (not CSV). Preview:", r.text.slice(0, 120));
    return;
  }
  const parsed = condense(r.text);
  console.log("columns:", parsed.columns.join(" | "));
  console.log("data rows:", parsed.row_count);
  console.log("preview:\n" + r.text.split("\n").slice(0, 8).join("\n"));
}

const session = new Session();
console.log("Node:", process.version, " Date:", date);

try {
  await session.login();
  console.log("Login OK. csrf:", session.csrf ? "scraped" : "(none)");

  const a = await post(buildVariant(session.csrf, true)); // select-all only
  summarize("A) select-all flag only (no hardcoded IDs)", a);

  const b = await post(buildVariant(session.csrf, false)); // control
  summarize("B) control (hSelServ=1,2,3,4,5)", b);

  console.log("\n--- verdict ---");
  if (!a.isHtml && !b.isHtml) {
    const ra = condense(a.text).row_count;
    const rb = condense(b.text).row_count;
    console.log(ra >= rb && ra > 0
      ? `A returned ${ra} rows vs control ${rb} -> SELECT-ALL FLAG WORKS. We can drop hardcoded hSelServ.`
      : `A returned ${ra} rows vs control ${rb} -> select-all alone is NOT equivalent; keep explicit IDs or fetch them dynamically.`);
  } else {
    console.log("One variant returned HTML — compare the previews above.");
  }
} catch (e) {
  console.error("Failed:", e.message);
}
