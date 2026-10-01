import { createHash, randomBytes } from "node:crypto";
import { decodeJwt } from "jose";
import type { Config } from "../config.js";

export interface EntraTokens {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number; // epoch ms
  user: { oid?: string; upn?: string; name?: string };
}

export const b64url = (b: Buffer) => b.toString("base64url");
export const newPkce = () => {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
};

/** Minimal Entra v2 confidential-client auth-code + refresh flow (delegated). */
export class EntraClient {
  constructor(private readonly cfg: Config) {}

  private get base() {
    return `https://login.microsoftonline.com/${this.cfg.entra.tenantId}/oauth2/v2.0`;
  }

  get redirectUri() {
    return `${this.cfg.publicUrl.origin}/oauth/callback`;
  }

  authorizeUrl(state: string, codeChallenge: string, loginHint?: string): string {
    const u = new URL(`${this.base}/authorize`);
    u.search = new URLSearchParams({
      client_id: this.cfg.entra.clientId,
      response_type: "code",
      redirect_uri: this.redirectUri,
      response_mode: "query",
      scope: this.cfg.entra.scopes,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      ...(loginHint ? { login_hint: loginHint } : {}),
    }).toString();
    return u.toString();
  }

  exchangeCode(code: string, codeVerifier: string): Promise<EntraTokens> {
    return this.token({ grant_type: "authorization_code", code, redirect_uri: this.redirectUri, code_verifier: codeVerifier });
  }

  refresh(refreshToken: string): Promise<EntraTokens> {
    return this.token({ grant_type: "refresh_token", refresh_token: refreshToken, scope: this.cfg.entra.scopes });
  }

  private async token(params: Record<string, string>): Promise<EntraTokens> {
    const res = await fetch(`${this.base}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: this.cfg.entra.clientId,
        client_secret: this.cfg.entra.clientSecret,
        ...params,
      }),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, any>;
    if (!res.ok) throw new Error(`Entra token error: ${body.error ?? res.status} ${body.error_description ?? ""}`.trim());
    // id_token comes straight from the token endpoint over TLS, so decoding without signature check is OK (OIDC core 3.1.3.7).
    const claims = body.id_token ? decodeJwt(body.id_token) : {};
    return {
      accessToken: body.access_token,
      refreshToken: body.refresh_token,
      expiresAt: Date.now() + Number(body.expires_in ?? 3600) * 1000,
      user: {
        oid: claims.oid as string | undefined,
        upn: (claims.preferred_username ?? claims.upn) as string | undefined,
        name: claims.name as string | undefined,
      },
    };
  }
}
