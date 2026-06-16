/**
 * Probe: does the by-service-group report return ALL service groups when we rely
 * only on chkAllSvcGrp=on, without the install-specific service group ID?
 *
 *   node test-svcgroup.js [YYYY-MM-DD]
 *
 * Logs in, then POSTs report 11059 twice and compares:
 *   A) "select all groups" — "Service Group" field removed and hSelSvcGrp emptied;
 *      relies on chkAllSvcGrp=on.
 *   B) "control"           — the captured payload as-is (Service Group=109860016).
 *
 * If A returns the same (or more) data rows as B, we can drop the hardcoded group ID.
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
const report = REPORTS.daily_by_service_group_queue_performance;
const GROUP_ID = "109860016"; // the captured install-specific service group id

function buildVariant(csrf, selectAllGroups) {
  // Control base = captured payload but with the group id RESTORED into the
  // "Service Group" checkbox (the stored payload keeps it; ensure it's present).
  const p = new URLSearchParams(report.payload);
  p.set("csrf-token", csrf || "");
  p.set("hRptOut", "csv");
  p.set("rptDt", date);
  if (!p.has("Service Group")) p.set("Service Group", GROUP_ID);
  p.set("hSelSvcGrp", GROUP_ID);
  if (selectAllGroups) {
    p.delete("Service Group"); // drop the specific group checkbox
    p.set("hSelSvcGrp", "");    // no explicit group — rely on chkAllSvcGrp=on
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
  console.log("preview:\n" + r.text.split("\n").slice(0, 10).join("\n"));
}

const session = new Session();
console.log("Node:", process.version, " Date:", date);

try {
  await session.login();
  console.log("Login OK. csrf:", session.csrf ? "scraped" : "(none)");

  const a = await post(buildVariant(session.csrf, true)); // all groups via flag
  summarize("A) chkAllSvcGrp=on only (no hardcoded group id)", a);

  const b = await post(buildVariant(session.csrf, false)); // control
  summarize("B) control (Service Group=109860016)", b);

  console.log("\n--- verdict ---");
  if (!a.isHtml && !b.isHtml) {
    const ra = condense(a.text).row_count;
    const rb = condense(b.text).row_count;
    console.log(ra >= rb && ra > 0
      ? `A returned ${ra} rows vs control ${rb} -> SELECT-ALL GROUPS WORKS. We can drop the hardcoded group id.`
      : `A returned ${ra} rows vs control ${rb} -> not equivalent; the group id is needed (or needs different flags).`);
  } else {
    console.log("One variant returned HTML — compare the previews above.");
  }
} catch (e) {
  console.error("Failed:", e.message);
}
