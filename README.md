# QMS Reporting MCP Server (test / mock) — Node.js

A minimal MCP server to validate the architecture:

```
AnythingLLM (host)  ->  Ollama / Qwen  ->  this MCP server  ->  mock report data
```

It exposes two tools:

- `get_report(report_type, branch_id?, date_from?, date_to?)` — returns mock QMS data
- `list_reports()` — lists the available report types

Once the loop works end-to-end, swap the mock in `server.js` (`mockData`) for a
real HTTP call to your QMS backend — see the TODO marker in that function.

## 1. Install dependencies

Requires Node.js 18+ (for built-in `fetch` when you move to the real API).

```bash
cd /Users/koo/Desktop/Claude/Projects/QMS/mcpreport
npm install
```

## 2. (Optional) quick local sanity check

```bash
node server.js
```

It starts and waits on stdio (no output is normal). Press Ctrl+C to stop.
AnythingLLM is what actually drives it.

## 3. Register in AnythingLLM

AnythingLLM reads MCP servers from a JSON file. On the **desktop app** it lives at
the storage folder, typically:

```
~/Library/Application Support/anythingllm-desktop/storage/plugins/anythingllm_mcp_servers.json
```

(On Docker, mount your config into the container's storage/plugins path.)

Add this entry — use absolute paths:

```json
{
  "mcpServers": {
    "qms-report": {
      "command": "node",
      "args": ["/Users/koo/Desktop/Claude/Projects/QMS/mcpreport/server.js"]
    }
  }
}
```

If `node` isn't found by AnythingLLM, use the absolute path to your Node binary
(run `which node` to get it), e.g. `/usr/local/bin/node` or an nvm path like
`/Users/koo/.nvm/versions/node/v20.x.x/bin/node`.

If the file already has other servers, just add `qms-report` inside the existing
`mcpServers` object.

## 3b. Provide credentials (auto-login — no cookies/tokens to manage)

The server logs into QMS itself: it POSTs the login, captures the `JSESSIONID`
cookie, scrapes the `csrf-token` from the response, and re-authenticates if the
session expires. You only set stable credentials via an `env` block (Windows
example shown):

```json
{
  "mcpServers": {
    "qms-report": {
      "command": "C:\\PROGRA~1\\nodejs\\node.exe",
      "args": ["C:\\qms\\mcpreport\\server.js"],
      "env": {
        "QMS_BASE_URL": "http://54.251.164.99:49999",
        "QMS_USER": "admin",
        "QMS_HASH_PWD": "8dc2fbace0...PASTE_FROM_LOGIN_PAYLOAD...16cc5ee"
      }
    }
  }
}
```

`QMS_HASH_PWD` is the **`hashPwd` value** from the login request's Payload (a
stable SHA-256 hash, not your plaintext password — copy it once from DevTools).
Alternatively, if `hashPwd == sha256(password)` on your install, set `QMS_PASS`
(plaintext) instead and the server will hash it for you.

These values don't expire, so you set them once. Keep this config out of git
(treat the password hash as a secret).

## 4. Start it in AnythingLLM

1. Open the **Agent Skills** page in AnythingLLM (this auto-starts MCP servers).
   You should see `qms-report` with tools `get_report` and `list_reports`.
2. Make sure the workspace LLM is your Ollama Qwen model.
3. Paste the contents of `system_prompt.txt` into the workspace **system prompt**.
4. In chat, invoke the agent (MCP tools only run in agent mode):

   ```
   @agent what was the ticket volume for branch BR-001 this week?
   @agent which counter served the most customers?
   @agent what's our no-show rate?
   ```

## Notes / gotchas

- **Tools fire only in `@agent` mode**, not normal chat.
- If AnythingLLM can't start the server, it's almost always the `command` path —
  use an absolute path to `node` and to `server.js`, and make sure you ran
  `npm install` in this folder so `node_modules` exists.
- **Windows (AnythingLLM desktop):** spawning `C:\Program Files\nodejs\node.exe`
  can fail with `ENOENT` because the space in `Program Files` trips the spawner.
  Use the 8.3 short path instead: `C:\\PROGRA~1\\nodejs\\node.exe` (verify the
  short name with `dir /x C:\`). Keep the project path space-free too.
- A 9B model will occasionally pick the wrong report or skip a parameter; the
  server validates inputs and returns a helpful `error` so the model can recover.
- The mock ignores most filters and returns fixed sample data — that's expected
  for an architecture test.
# mcpreport
