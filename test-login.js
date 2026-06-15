/**
 * Standalone login tester — run on a machine that can reach the QMS server.
 *
 *   node test-login.js
 *
 * Reports: status, all Set-Cookie headers, whether a JSESSIONID came back, and
 * whether a csrf-token could be scraped from the response HTML.
 *
 * Uses the built-in http module (no global fetch needed), so it works on any
 * Node version. Override defaults with env vars: QMS_BASE_URL, QMS_USER, QMS_HASH_PWD.
 */

import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

const BASE_URL = process.env.QMS_BASE_URL || "http://54.251.164.99:49999";
const USER = process.env.QMS_USER || "admin";
const HASH_PWD =
  process.env.QMS_HASH_PWD ||
  "8dc2fbace07fc965e0030e9ec09df445810bbb73579f4c5c58c106bdf16cc5ee";
const LOGIN_PATH = "/QMS700i/servlet/my.com.gms.qms.mnt.servlets.CSignOn?param=SUBMIT";

function request(urlStr, { method = "GET", headers = {}, body = "" } = {}) {
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
    req.setTimeout(25000, () => req.destroy(new Error("timeout")));
    if (data) req.write(data);
    req.end();
  });
}

function scrapeCsrf(html) {
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

const body = new URLSearchParams({
  txtUsrId: USER,
  txtPwd: "",
  hashPwd: HASH_PWD,
  randomNum: "0",
  mod: "",
  urlRedirect: "",
}).toString();

console.log("Node:", process.version);
console.log(`POST ${BASE_URL}${LOGIN_PATH}`);
console.log(`user=${USER} hashPwd=${HASH_PWD.slice(0, 10)}...\n`);

try {
  const resp = await request(BASE_URL + LOGIN_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  console.log("Status:", resp.status);
  console.log("Content-Type:", resp.headers["content-type"]);

  console.log("\nSet-Cookie headers:");
  resp.setCookies.forEach((c) => console.log("  " + c));

  const jsession = resp.setCookies.find((c) => c.startsWith("JSESSIONID="));
  console.log("\nJSESSIONID:", jsession ? "FOUND -> " + jsession.split(";")[0] : "NOT FOUND");

  const csrf = scrapeCsrf(resp.text);
  console.log("csrf-token:", csrf ? "FOUND -> " + csrf : "NOT FOUND");

  if (!csrf) {
    const idx = resp.text.toLowerCase().indexOf("csrf");
    console.log(
      idx >= 0
        ? "\n(csrf appears in HTML — share this so the regex can be tuned:)\n" +
            resp.text.slice(idx - 40, idx + 120)
        : "\n(no 'csrf' substring in the response — token may be on a different page)"
    );
    console.log("\nResponse length:", resp.text.length, "bytes");
  }
} catch (e) {
  console.error("Request failed:", e.message);
}
