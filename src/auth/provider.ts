import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Request, Response } from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { InvalidGrantError, InvalidTokenError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { EntraClient, newPkce, type EntraTokens } from "./entra.js";

const ACCESS_TTL_S = 3600;
const CODE_TTL_MS = 5 * 60_000;
const PENDING_TTL_MS = 10 * 60_000;
const REFRESH_TTL_MS = 30 * 24 * 3600_000;

const rand = () => randomBytes(32).toString("base64url");
const hash = (t: string) => createHash("sha256").update(t).digest("hex");

interface Pending {
  clientId: string;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  upstreamVerifier: string;
  expires: number;
}
interface Code {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  entra: EntraTokens;
  expires: number;
}
/** One per user sign-in; holds the delegated Entra tokens. Memory only. */
export interface Session {
  id: string;
  clientId: string;
  entra: EntraTokens;
  refreshing?: Promise<void>;
}

class ClientsStore implements OAuthRegisteredClientsStore {
  private clients = new Map<string, OAuthClientInformationFull>();
  constructor(private readonly file?: string) {
    if (file && fs.existsSync(file)) {
      for (const c of JSON.parse(fs.readFileSync(file, "utf8")) as OAuthClientInformationFull[]) this.clients.set(c.client_id, c);
    }
  }
  getClient(id: string) {
    return this.clients.get(id);
  }
  registerClient(c: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">): OAuthClientInformationFull {
    const full = { ...c, client_id: randomBytes(16).toString("hex"), client_id_issued_at: Math.floor(Date.now() / 1000) };
    this.clients.set(full.client_id, full);
    if (this.file) {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify([...this.clients.values()]), { mode: 0o600 });
    }
    return full;
  }
}

/**
 * OAuth authorization server for MCP clients (Claude Desktop etc.) that delegates user sign-in to Entra.
 * Entra has no dynamic client registration, so this gateway registers clients itself, runs the Entra
 * code flow with its own app registration, and issues opaque gateway tokens mapped to the user's Entra tokens.
 */
export class EntraProxyProvider implements OAuthServerProvider {
  readonly clientsStore: ClientsStore;
  private pending = new Map<string, Pending>();
  private codes = new Map<string, Code>();
  private access = new Map<string, { sessionId: string; expires: number }>();
  private refreshTokens = new Map<string, { sessionId: string; clientId: string; expires: number }>();
  private sessions = new Map<string, Session>();

  constructor(private readonly entra: EntraClient, clientStorePath?: string) {
    this.clientsStore = new ClientsStore(clientStorePath);
    setInterval(() => this.sweep(), 60_000).unref();
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    const id = rand();
    const pkce = newPkce();
    this.pending.set(id, {
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      state: params.state,
      codeChallenge: params.codeChallenge,
      upstreamVerifier: pkce.verifier,
      expires: Date.now() + PENDING_TTL_MS,
    });
    res.redirect(this.entra.authorizeUrl(id, pkce.challenge));
  }

  /** Express handler for GET /oauth/callback (Entra redirects here). */
  callback = async (req: Request, res: Response): Promise<void> => {
    const { code, state, error, error_description } = req.query as Record<string, string | undefined>;
    const p = state ? this.pending.get(state) : undefined;
    if (!p || p.expires < Date.now()) {
      res.status(400).send("Unknown or expired sign-in request. Return to Claude and retry.");
      return;
    }
    this.pending.delete(state!);
    const back = (params: Record<string, string>) => {
      const u = new URL(p.redirectUri);
      for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
      if (p.state) u.searchParams.set("state", p.state);
      res.redirect(u.toString());
    };
    if (error || !code) return back({ error: error ?? "access_denied", ...(error_description ? { error_description } : {}) });
    try {
      const entra = await this.entra.exchangeCode(code, p.upstreamVerifier);
      const gwCode = rand();
      this.codes.set(hash(gwCode), {
        clientId: p.clientId,
        codeChallenge: p.codeChallenge,
        redirectUri: p.redirectUri,
        entra,
        expires: Date.now() + CODE_TTL_MS,
      });
      back({ code: gwCode });
    } catch (e) {
      console.error("entra code exchange failed", (e as Error).message);
      back({ error: "server_error", error_description: "Sign-in with Entra failed" });
    }
  };

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string): Promise<string> {
    const c = this.codes.get(hash(code));
    if (!c || c.clientId !== client.client_id || c.expires < Date.now()) throw new InvalidGrantError("Invalid authorization code");
    return c.codeChallenge;
  }

  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, _v?: string, redirectUri?: string): Promise<OAuthTokens> {
    const key = hash(code);
    const c = this.codes.get(key);
    this.codes.delete(key); // single use
    if (!c || c.clientId !== client.client_id || c.expires < Date.now()) throw new InvalidGrantError("Invalid authorization code");
    if (redirectUri && redirectUri !== c.redirectUri) throw new InvalidGrantError("redirect_uri mismatch");
    const session: Session = { id: rand(), clientId: client.client_id, entra: c.entra };
    this.sessions.set(session.id, session);
    return this.issue(session);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
    const key = hash(refreshToken);
    const r = this.refreshTokens.get(key);
    const session = r && this.sessions.get(r.sessionId);
    if (!r || !session || r.clientId !== client.client_id || r.expires < Date.now()) throw new InvalidGrantError("Invalid refresh token");
    this.refreshTokens.delete(key); // rotate
    return this.issue(session);
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const a = this.access.get(hash(token));
    const s = a && this.sessions.get(a.sessionId);
    if (!a || !s || a.expires < Date.now()) throw new InvalidTokenError("Invalid or expired token");
    return {
      token,
      clientId: s.clientId,
      scopes: [],
      expiresAt: Math.floor(a.expires / 1000),
      extra: { sessionId: s.id, user: s.entra.user },
    };
  }

  async revokeToken(_c: OAuthClientInformationFull, req: OAuthTokenRevocationRequest): Promise<void> {
    const key = hash(req.token);
    const sid = this.access.get(key)?.sessionId ?? this.refreshTokens.get(key)?.sessionId;
    if (sid) this.dropSession(sid);
  }

  /** Current delegated ADO access token for a session, refreshing via Entra when near expiry. */
  async getAdoToken(sessionId: string): Promise<string> {
    const s = this.sessions.get(sessionId);
    if (!s) throw new InvalidTokenError("Session ended; please reconnect.");
    if (s.entra.expiresAt - Date.now() < 120_000) {
      s.refreshing ??= this.refreshSession(s).finally(() => (s.refreshing = undefined));
      await s.refreshing;
    }
    return s.entra.accessToken;
  }

  private async refreshSession(s: Session): Promise<void> {
    if (!s.entra.refreshToken) throw new InvalidTokenError("No Entra refresh token; please reconnect.");
    try {
      const fresh = await this.entra.refresh(s.entra.refreshToken);
      s.entra = { ...fresh, refreshToken: fresh.refreshToken ?? s.entra.refreshToken, user: s.entra.user };
    } catch (e) {
      this.dropSession(s.id); // revoked / CA policy / password change -> force re-auth
      throw new InvalidTokenError(`Entra refresh failed; please reconnect. (${(e as Error).message})`);
    }
  }

  private issue(s: Session): OAuthTokens {
    const at = rand(), rt = rand();
    this.access.set(hash(at), { sessionId: s.id, expires: Date.now() + ACCESS_TTL_S * 1000 });
    this.refreshTokens.set(hash(rt), { sessionId: s.id, clientId: s.clientId, expires: Date.now() + REFRESH_TTL_MS });
    return { access_token: at, token_type: "Bearer", expires_in: ACCESS_TTL_S, refresh_token: rt };
  }

  private dropSession(id: string) {
    this.sessions.delete(id);
    for (const [k, v] of this.access) if (v.sessionId === id) this.access.delete(k);
    for (const [k, v] of this.refreshTokens) if (v.sessionId === id) this.refreshTokens.delete(k);
  }

  private sweep() {
    const now = Date.now();
    for (const m of [this.pending, this.codes, this.access, this.refreshTokens]) {
      for (const [k, v] of m as Map<string, { expires: number }>) if (v.expires < now) m.delete(k);
    }
  }
}
