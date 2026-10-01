import { z } from "zod";

const list = (v: string | undefined) =>
  (v ?? "").split(",").map((s) => s.trim()).filter(Boolean);

const ADO_RESOURCE = "499b84ac-1321-427f-aa17-267ca6975798";

const Env = z.object({
  PUBLIC_URL: z.string().url(),
  PORT: z.coerce.number().default(3000),
  TRUST_PROXY: z.string().optional(),
  ENTRA_TENANT_ID: z.string().min(1),
  ENTRA_CLIENT_ID: z.string().min(1),
  ENTRA_CLIENT_SECRET: z.string().min(1),
  ENTRA_SCOPES: z
    .string()
    .default(`${ADO_RESOURCE}/user_impersonation offline_access openid profile`),
  ADO_ORG: z.string().min(1),
  ADO_ALLOWED_PROJECTS: z.string().optional(),
  ADO_ALLOWED_WORK_ITEM_TYPES: z.string().optional(),
  ADO_ALLOWED_OPERATIONS: z.string().default("read,create,update"),
  CLIENT_STORE_PATH: z.string().optional(),
});

export type Operation = "read" | "create" | "update";

export interface Config {
  publicUrl: URL;
  port: number;
  trustProxy: boolean;
  entra: { tenantId: string; clientId: string; clientSecret: string; scopes: string };
  adoOrg: string;
  policy: {
    projects: string[];
    workItemTypes: string[];
    operations: Operation[];
  };
  clientStorePath?: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const e = Env.parse(env);
  const ops = list(e.ADO_ALLOWED_OPERATIONS) as Operation[];
  for (const o of ops) {
    if (!["read", "create", "update"].includes(o)) throw new Error(`Unknown operation: ${o}`);
  }
  return {
    publicUrl: new URL(e.PUBLIC_URL.replace(/\/+$/, "")),
    port: e.PORT,
    trustProxy: e.TRUST_PROXY === "1" || e.TRUST_PROXY === "true",
    entra: {
      tenantId: e.ENTRA_TENANT_ID,
      clientId: e.ENTRA_CLIENT_ID,
      clientSecret: e.ENTRA_CLIENT_SECRET,
      scopes: e.ENTRA_SCOPES,
    },
    adoOrg: e.ADO_ORG,
    policy: {
      projects: list(e.ADO_ALLOWED_PROJECTS),
      workItemTypes: list(e.ADO_ALLOWED_WORK_ITEM_TYPES),
      operations: ops,
    },
    clientStorePath: e.CLIENT_STORE_PATH,
  };
}
