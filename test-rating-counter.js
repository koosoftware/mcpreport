/**
 * Probe: for the Customer Rating by-counter report, does omitting the counter ids
 * (rely on chkAllCnt=on) return all counters, or is the counter list required?
 *
 *   node test-rating-counter.js [YYYY-MM-DD]
 *
 * Logs in, then POSTs report 21003 twice and compares:
 *   A) "no counters" — hSelCounter empty, no Counter fields (the stored payload as-is).
 *   B) "control"     — full counter list (Counter 1..15) + hSelCounter.
 *
 * If A returns the same (or more) rows as B, this report does NOT need counters and can
 * drop `counters: true`. If A errors / returns fewer, it needs counters (current behavior).
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
const report = REPORTS.daily_customer_rating_by_counter;

const N = 15;
const COUNTER_FIELDS = Array.from({ length: N }, (_, i) => `&Counter+${i + 1}=${i + 1}`).join("");
const COUNTER_IDS = Array.from({ length: N }, (_, i) => i + 1).join(",");

function buildVariant(csrf, mode) {
  const p = new URLSearchParams(report.payload);
  p.set("csrf-token", csrf || "");
  p.set("hRptOut", "csv");
  p.set("rptDt", date);
  p.set("hSelCounter", ""); // start with none
  if (mode === "indicatorY") {
    p.set("hCounterSelInd", "Y"); // chkAllCnt=on already present
  } else if (mode === "indicatorN") {
    p.set("hCounterSelInd", "N");
  } else if (mode === "control") {
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

function summarize(label, r) {
  console.log(`\n=== ${label} ===`);
  console.log("status:", r.status, " content-type:", r.ctype);
  const head = r.text.split("\n")[0];
  console.log("first line:", head.slice(0, 140));
  if (!r.isHtml && !head.startsWith("Unable")) {
    const parsed = condense(r.text);
    console.log("data rows:", parsed.row_count);
    console.log("preview:\n" + r.text.split("\n").slice(0, 6).join("\n"));
  }
}

function rowsOf(r) {
  const head = r.text.split("\n")[0];
  if (r.isHtml || head.startsWith("Unable")) return -1;
  return condense(r.text).row_count;
}

const session = new Session();
console.log("Node:", process.version, " Date:", date);

try {
  await session.login();
  console.log("Login OK. csrf:", session.csrf ? "scraped" : "(none)");

  const a = await post(buildVariant(session.csrf, "indicatorY"));
  summarize("A) chkAllCnt=on, hCounterSelInd=Y, no counter ids", a);

  const c = await post(buildVariant(session.csrf, "indicatorN"));
  summarize("C) chkAllCnt=on, hCounterSelInd=N, no counter ids", c);

  const b = await post(buildVariant(session.csrf, "control"));
  summarize("B) control (full counter list)", b);

  const rb = rowsOf(b);
  console.log("\n--- verdict ---");
  const cands = [["A (hCounterSelInd=Y)", rowsOf(a)], ["C (hCounterSelInd=N)", rowsOf(c)]];
  const winner = cands.find(([, n]) => n >= rb && n > 0);
  console.log(winner
    ? `${winner[0]} returned ${winner[1]} rows vs control ${rb} -> NO counters needed. Can drop 'counters: true'.`
    : `Neither A nor C matched control ${rb} (A=${rowsOf(a)}, C=${rowsOf(c)}) -> counters ARE required (keep 'counters: true').`);
} catch (e) {
  console.error("Failed:", e.message);
}
