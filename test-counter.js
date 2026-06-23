/**
 * Probe: can the by-counter report return ALL counters without the install-specific
 * counter ids? Tests three variants:
 *
 *   node test-counter.js [YYYY-MM-DD]
 *
 *   A) indicator=Y : chkAllCnt=on, hSelCounter empty, hCounterSelInd=Y  (original; failed)
 *   C) indicator=N : chkAllCnt=on, hSelCounter empty, hCounterSelInd=N  (candidate fix)
 *   B) control     : full counter list (Counter 1..15) + hSelCounter, hCounterSelInd=Y
 *
 * If C matches the control's rows, the report can be made portable (no hardcoded ids).
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
const report = REPORTS.daily_counter_by_service_queue_performance;

const N = 15;
const COUNTER_FIELDS = Array.from({ length: N }, (_, i) => `&Counter+${i + 1}=${i + 1}`).join("");
const COUNTER_IDS = Array.from({ length: N }, (_, i) => i + 1).join(",");

// Base = stored payload with the counter ids/fields stripped out.
function basePayload() {
  const p = new URLSearchParams(report.payload);
  for (let i = 1; i <= N; i++) p.delete(`Counter ${i}`);
  p.set("hSelCounter", "");
  return p;
}

function buildVariant(csrf, mode) {
  const p = basePayload();
  p.set("csrf-token", csrf || "");
  p.set("hRptOut", "csv");
  p.set("rptDt", date);
  if (mode === "indicatorY") {
    p.set("hCounterSelInd", "Y");
  } else if (mode === "indicatorN") {
    p.set("hCounterSelInd", "N");
  } else if (mode === "selectAllFlag") {
    // Try the analogous select-all flag (not present in the captured form).
    p.set("hCounterSelInd", "Y");
    p.set("hSelectAllCounterFlg", "Y");
  } else if (mode === "control") {
    p.set("hCounterSelInd", "Y");
    let body = p.toString().replace("&chkAllCnt=on", "&chkAllCnt=on" + COUNTER_FIELDS);
    const cp = new URLSearchParams(body);
    cp.set("hSelCounter", COUNTER_IDS);
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

function rowsOf(r) {
  if (r.isHtml) return -1;
  return condense(r.text).row_count;
}

function summarize(label, r) {
  console.log(`\n=== ${label} ===`);
  console.log("status:", r.status, " content-type:", r.ctype);
  const head = r.text.split("\n")[0];
  console.log("first line:", head.slice(0, 120));
  if (!r.isHtml && !head.startsWith("Unable")) console.log("data rows:", condense(r.text).row_count);
}

const session = new Session();
console.log("Node:", process.version, " Date:", date);

try {
  await session.login();
  console.log("Login OK. csrf:", session.csrf ? "scraped" : "(none)");

  const a = await post(buildVariant(session.csrf, "indicatorY"));
  summarize("A) chkAllCnt=on, hCounterSelInd=Y, no ids (original)", a);

  const c = await post(buildVariant(session.csrf, "indicatorN"));
  summarize("C) chkAllCnt=on, hCounterSelInd=N, no ids (candidate)", c);

  const d = await post(buildVariant(session.csrf, "selectAllFlag"));
  summarize("D) chkAllCnt=on, hSelectAllCounterFlg=Y, no ids (candidate)", d);

  const b = await post(buildVariant(session.csrf, "control"));
  summarize("B) control (full counter list)", b);

  const rb = rowsOf(b);
  console.log("\n--- verdict ---");
  const candidates = [["C (hCounterSelInd=N)", rowsOf(c)], ["D (hSelectAllCounterFlg=Y)", rowsOf(d)]];
  const winner = candidates.find(([, n]) => n >= rb && n > 0);
  if (winner) {
    console.log(`${winner[0]} returned ${winner[1]} rows vs control ${rb} -> WORKS. Report can be portable.`);
  } else {
    console.log(`Neither candidate matched control ${rb} (C=${rowsOf(c)}, D=${rowsOf(d)}) -> keep hardcoded counter ids.`);
  }
} catch (e) {
  console.error("Failed:", e.message);
}
