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
      "monthly customer rating by teller",
      "daily idle log",
      "queue performance by service",
      "periodically rating performance by question",
      "how many tickets today",
      "counter performance this month",
      "waiting time distribution",
      "sms log last month",
      "rating distribution pattern by hour",
      "transaction log",
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
