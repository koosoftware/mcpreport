/**
 * Offline test of the find_reports search (no network/login needed).
 *
 *   node test-find.js "monthly customer rating by teller"
 *   node test-find.js            # runs a built-in set of sample queries
 *
 * Prints the ranked shortlist the model would receive from find_reports.
 */

const { searchReports } = await import("./qms-core.js");

const arg = process.argv.slice(2).join(" ").trim();
const queries = arg
  ? [arg]
  : [
      // sibling cases that used to tie — the right report should now rank #1
      "queue performance by service",
      "queue performance by service group",
      "rating distribution by teller",
      "rating distribution by teller by question",
      "rating performance by question",
      "rating distribution by question",
      // grain should float the right period to the top
      "monthly customer rating by teller",
      "transaction log this month",
      // general
      "daily idle log",
      "sms log last month",
      "customer rating by counter",
      "rating distribution pattern by hour",
      "how many tickets today",
    ];

for (const q of queries) {
  console.log(`\nQ: ${q}`);
  const matches = searchReports(q, 6);
  if (!matches.length) {
    console.log("   (no match)");
    continue;
  }
  for (const m of matches) {
    console.log(`   [${m.score}] ${m.key}  (${m.input})`);
  }
}
