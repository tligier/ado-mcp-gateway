import express from "express";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { loadConfig } from "./config.js";
import { Policy } from "./policy.js";
import { EntraClient } from "./auth/entra.js";
import { EntraProxyProvider } from "./auth/provider.js";
import { createMcpServer } from "./mcp/tools.js";

const cfg = loadConfig();
const provider = new EntraProxyProvider(new EntraClient(cfg), cfg.clientStorePath);
const policy = new Policy(cfg.policy);
const mcpUrl = new URL("/mcp", cfg.publicUrl);

const app = express();
if (cfg.trustProxy) app.set("trust proxy", 1);
app.disable("x-powered-by");

app.get("/healthz", (_req, res) => void res.json({ ok: true }));
app.use(mcpAuthRouter({ provider, issuerUrl: cfg.publicUrl, resourceServerUrl: mcpUrl, resourceName: "Azure DevOps work items" }));
app.get("/oauth/callback", provider.callback);

app.post(
  "/mcp",
  requireBearerAuth({ verifier: provider, resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(mcpUrl) }),
  express.json({ limit: "1mb" }),
  async (req, res) => {
    // Stateless: a fresh server+transport per request, bound to the caller's session via req.auth.
    const server = createMcpServer({ cfg, policy, getToken: (id) => provider.getAdoToken(id) });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (e) {
      console.error(e);
      if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal error" }, id: null });
    }
  },
);
for (const m of ["get", "delete"] as const) {
  app[m]("/mcp", (_req, res) => void res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed (stateless server)" }, id: null }));
}

app.listen(cfg.port, () => console.log(`ado-mcp-gateway listening on :${cfg.port}, MCP at ${mcpUrl}`));
