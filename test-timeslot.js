/**
 * Probe: does the pattern-analysis report return ALL time-of-day slots when we
 * rely only on chkAllTod=on, without the install-specific time-slot ids?
 *
 *   node test-timeslot.js [YYYY-MM-DD]
 *
 * Logs in, then POSTs report 11033 twice and compares:
 *   A) "select all" — no time-slot fields (hSelDayTimeSlot empty); relies on
 *      chkAllTod=on + hDayTimeSlotSelInd=Y. This is the stored portable payload.
 *   B) "control"    — the captured payload WITH the full time-slot list (07:00..21:00).
 *
 * If A returns the same (or more) rows as B, the stored portable payload is correct.
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
const report = REPORTS.daily_pattern_analysis_queue_performance;

// Captured time-of-day slot checkbox fields (hour=id) and the hSelDayTimeSlot id list.
const SLOT_FIELDS =
  "&07%3A00=17&08%3A00=18&09%3A00=19&10%3A00=20&11%3A00=21&12%3A00=22&13%3A00=23" +
  "&14%3A00=24&15%3A00=25&16%3A00=26&17%3A00=27&18%3A00=28&19%3A00=29&20%3A00=30&21%3A00=31";
const SLOT_IDS = "17,18,19,20,21,22,23,24,25,26,27,28,29,30,31";

function buildVariant(csrf, withSlots) {
  const p = new URLSearchParams(report.payload);
  p.set("csrf-token", csrf || "");
  p.set("hRptOut", "csv");
  p.set("rptDt", date);
  if (withSlots) {
    let body = p.toString();
    body = body.replace("&chkAllTod=on", "&chkAllTod=on" + SLOT_FIELDS);
    const cp = new URLSearchParams(body);
    cp.set("hSelDayTimeSlot", SLOT_IDS);
    return cp.toString();
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
  if (r.isHtml) { console.log("-> HTML preview:", r.text.slice(0, 120)); return; }
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

  const a = await post(buildVariant(session.csrf, false)); // flags only
  summarize("A) chkAllTod=on only (no slot ids)", a);

  const b = await post(buildVariant(session.csrf, true)); // control with slots
  summarize("B) control (full time-slot list)", b);

  console.log("\n--- verdict ---");
  if (!a.isHtml && !b.isHtml) {
    const ra = condense(a.text).row_count;
    const rb = condense(b.text).row_count;
    console.log(ra >= rb && ra > 0
      ? `A returned ${ra} rows vs control ${rb} -> SELECT-ALL TIME SLOTS WORKS. Stored payload is correct.`
      : `A returned ${ra} rows vs control ${rb} -> not equivalent; the time-slot list is needed.`);
  } else {
    console.log("One variant returned HTML — compare the previews above.");
  }
} catch (e) {
  console.error("Failed:", e.message);
}
