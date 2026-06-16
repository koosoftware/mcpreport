/**
 * Probe: does the by-teller report return ALL tellers when we rely only on the
 * select-all flags, without the install-specific teller list?
 *
 *   node test-teller.js [YYYY-MM-DD]
 *
 * Logs in, then POSTs report 11025 twice and compares:
 *   A) "select all"  — no teller list (hSelTeller empty); relies on chkAllTr=on +
 *      hSelectAllTellerFlg=Y. This is the stored portable payload.
 *   B) "control"     — the captured payload WITH the full teller list.
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
const report = REPORTS.daily_by_service_teller_queue_performance;

// Captured teller list (name=id checkbox fields) and the hSelTeller id list, used
// only to build the control variant.
const TELLER_FIELDS =
  "&Adam+Farhan=58&Ahmad+Muslihuddin+Rozlan=47&Alif+Faizuddin+Jamaluddin=50" +
  "&Amelia+Japar=49&AZURIN+LANI=34&Fatin+Shakirah=42&Hafeezul=18&Hafizul+Azwan=36" +
  "&Haniza+Zaharan=69&Ida+Faridah+Mohd+Rosdi=20&Kamil=16&K+S+Apparavoo=21" +
  "&Masniza+Ismail=70&MOHARAM+ALI=14&Mohd+Azril+=38&Mohd+Nordin+Abd+Rahman=32" +
  "&MOHD+ZAMANI+MOHD+YUSOFF=7&MUHAMAD+AZIZI+MUHAMAD+APANDI=4&Muhammad+Arif+Syazwan=53" +
  "&Muhammad+Nazreen+Bin+Abdul+Nasir=30&Nabilah+Abu+Hassan+Alshari=48&NAZIHA+MOHAMAD=25" +
  "&Noraleya+Maisara+Ahmad+Faisal=66&NOR+ATIKAH+MOHD+PAUZI=13&NORMAZATULAKMAR+RAZALI=40" +
  "&Nur+Farahwahida+Abdul+Rashid=55&NURFASEEHA=43&Nur+Mazlen+Abd+Rani=45" +
  "&Nur+Syafiqah+Abd+A+Razak=54&NurSyazwani+Hassan=35&Nurul+Jannah+Hazahar=52" +
  "&RAMANADASS+SATHIASEELAN=2&Saidi+Yaakob=33&Shanin+Lyka+Ehsan=44&Siti+Nurfarahanis+Omar=67" +
  "&SOFEA+ADORA=41&Surita+Abdul+Rahman=51&Thivyaa+Deepakaran=65&VERONICA+KOW+LI+LIAN=8&Zulaina=57";
const TELLER_IDS =
  "58,47,50,49,34,42,18,36,69,20,16,21,70,14,38,32,7,4,53,30,48,25,66,13,40,55,43,45,54,35,52,2,33,44,67,41,51,65,8,57,72";

function buildVariant(csrf, withTellerList) {
  const p = new URLSearchParams(report.payload);
  p.set("csrf-token", csrf || "");
  p.set("hRptOut", "csv");
  p.set("rptDt", date);
  if (withTellerList) {
    // Re-add the captured teller checkboxes + the hSelTeller id list (control).
    let body = p.toString();
    body = body.replace("&chkAllTr=on", "&chkAllTr=on" + TELLER_FIELDS);
    const cp = new URLSearchParams(body);
    cp.set("hSelTeller", TELLER_IDS);
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
  console.log("preview:\n" + r.text.split("\n").slice(0, 6).join("\n"));
}

const session = new Session();
console.log("Node:", process.version, " Date:", date);

try {
  await session.login();
  console.log("Login OK. csrf:", session.csrf ? "scraped" : "(none)");

  const a = await post(buildVariant(session.csrf, false)); // flags only
  summarize("A) select-all flags only (no teller list)", a);

  const b = await post(buildVariant(session.csrf, true)); // control with teller list
  summarize("B) control (full teller list)", b);

  console.log("\n--- verdict ---");
  if (!a.isHtml && !b.isHtml) {
    const ra = condense(a.text).row_count;
    const rb = condense(b.text).row_count;
    console.log(ra >= rb && ra > 0
      ? `A returned ${ra} rows vs control ${rb} -> SELECT-ALL TELLERS WORKS. Stored payload is correct.`
      : `A returned ${ra} rows vs control ${rb} -> not equivalent; the teller list is needed.`);
  } else {
    console.log("One variant returned HTML — compare the previews above.");
  }
} catch (e) {
  console.error("Failed:", e.message);
}
