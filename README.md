# ado-mcp-gateway

Small remote MCP server (Streamable HTTP) exposing a few Azure DevOps work-item tools. Every ADO call runs with the **signed-in user's delegated Entra token** — no shared PAT; `Created By` / `Changed By` are the real user.

## Tools
- `ado_get_projects`, `ado_get_work_item_types`
- `ado_get_work_item`, `ado_search_work_items` (structured filters → safe WIQL, one project)
- `ado_create_work_item`, `ado_update_work_item`
- No delete / permissions / project admin tools.

## How auth works
- Gateway = OAuth 2.1 authorization server for MCP clients (DCR, PKCE, `/.well-known/*`), delegating sign-in to Entra (Entra has no DCR, hence the proxy).
- Client → `/authorize` → Entra login (MFA/CA apply) → `/oauth/callback` → gateway code → opaque gateway tokens.
- Entra access/refresh tokens stay server-side (memory), refreshed on demand; revoked/failed refresh forces re-auth.

## Entra setup
- App registration, **Web** platform, redirect URI `${PUBLIC_URL}/oauth/callback`, client secret.
- API permission: Azure DevOps → delegated `user_impersonation` (+ `openid profile offline_access`); grant admin consent if required.
- Note: `vso.*` scopes are for legacy ADO OAuth, not Entra. Entra tokens carry `user_impersonation` only, so narrowing is done by tool surface + `ADO_ALLOWED_*` policy here.
- Entra tenant must be connected to the ADO org.

## Run
```
cp .env.example .env   # fill in
npm i && npm run build && node --env-file=.env dist/index.js
```
- Claude Code: `claude mcp add --transport http ado https://host/mcp`
- Claude Desktop: add as a custom connector with URL `https://host/mcp`.

## Verify identity first (plan step 1–2)
- Connect, call `ado_create_work_item` on a test project, check Created By / Changed By / History is the user.

## Limits / next steps
- State (sessions, codes) is in memory → single instance, restart = re-auth. Swap `EntraProxyProvider` maps for Redis/Cosmos to scale out.
- Set `CLIENT_STORE_PATH` to keep DCR clients across restarts.
- Must be served over HTTPS (Front Door/App Service/Container Apps); set `TRUST_PROXY=1` behind it.
- Not evaluated: proxying Microsoft's hosted ADO MCP (its Entra flow isn't supported by Claude Desktop).
