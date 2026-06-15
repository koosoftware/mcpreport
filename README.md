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
- A 9B model will occasionally pick the wrong report or skip a parameter; the
  server validates inputs and returns a helpful `error` so the model can recover.
- The mock ignores most filters and returns fixed sample data — that's expected
  for an architecture test.
# mcpreport
