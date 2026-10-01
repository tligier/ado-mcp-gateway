const API = "api-version=7.1";

export class AdoError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

export interface WorkItem {
  id: number;
  rev?: number;
  fields: Record<string, unknown>;
  relations?: unknown[];
  url?: string;
}

export interface PatchOp {
  op: "add" | "replace" | "remove" | "test";
  path: string;
  value?: unknown;
}

/** Thin Azure DevOps REST client. Every call is made with the *user's* delegated bearer token. */
export class AdoClient {
  constructor(private readonly org: string, private readonly token: string) {}

  private async req<T>(method: string, path: string, body?: unknown, contentType = "application/json"): Promise<T> {
    const res = await fetch(`https://dev.azure.com/${encodeURIComponent(this.org)}/${path}`, {
      method,
      redirect: "manual", // ADO redirects to a sign-in page on bad tokens
      headers: {
        authorization: `Bearer ${this.token}`,
        accept: "application/json",
        ...(body !== undefined ? { "content-type": contentType } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const isJson = res.headers.get("content-type")?.includes("json");
    if (res.status === 203 || (res.status >= 300 && res.status < 400) || (res.ok && !isJson && text))
      throw new AdoError("Azure DevOps rejected the delegated token (not authenticated). Reconnect the MCP server.", 401);
    if (!res.ok) {
      let msg = text.slice(0, 500);
      try {
        msg = (JSON.parse(text) as { message?: string }).message ?? msg;
      } catch {}
      throw new AdoError(`Azure DevOps ${res.status}: ${msg}`, res.status);
    }
    return (text ? JSON.parse(text) : undefined) as T;
  }

  listProjects(): Promise<{ value: { id: string; name: string; description?: string; state: string }[] }> {
    return this.req("GET", `_apis/projects?${API}&$top=500`);
  }

  getWorkItemTypes(project: string): Promise<{ value: { name: string; description?: string; referenceName: string }[] }> {
    return this.req("GET", `${encodeURIComponent(project)}/_apis/wit/workitemtypes?${API}`);
  }

  getWorkItem(id: number, opts: { fields?: string[]; expandRelations?: boolean } = {}): Promise<WorkItem> {
    const q = opts.fields?.length ? `&fields=${opts.fields.map(encodeURIComponent).join(",")}` : opts.expandRelations ? "&$expand=relations" : "";
    return this.req("GET", `_apis/wit/workitems/${id}?${API}${q}`);
  }

  createWorkItem(project: string, type: string, ops: PatchOp[]): Promise<WorkItem> {
    return this.req("POST", `${encodeURIComponent(project)}/_apis/wit/workitems/$${encodeURIComponent(type)}?${API}`, ops, "application/json-patch+json");
  }

  updateWorkItem(id: number, ops: PatchOp[]): Promise<WorkItem> {
    return this.req("PATCH", `_apis/wit/workitems/${id}?${API}`, ops, "application/json-patch+json");
  }

  async queryWiql(project: string, wiql: string, top: number): Promise<number[]> {
    const r = await this.req<{ workItems?: { id: number }[] }>("POST", `${encodeURIComponent(project)}/_apis/wit/wiql?${API}&$top=${top}`, { query: wiql });
    return (r.workItems ?? []).map((w) => w.id);
  }

  async getWorkItemsBatch(ids: number[], fields: string[]): Promise<WorkItem[]> {
    if (!ids.length) return [];
    const r = await this.req<{ value: WorkItem[] }>("POST", `_apis/wit/workitemsbatch?${API}`, { ids, fields });
    return r.value;
  }
}

export const toPatch = (fields: Record<string, unknown>): PatchOp[] =>
  Object.entries(fields)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => ({ op: "add", path: `/fields/${k}`, value: v }));

const lit = (s: string) => `'${s.replaceAll("'", "''")}'`;

export interface SearchFilters {
  project: string;
  text?: string;
  type?: string;
  state?: string;
  assignedTo?: string;
  areaPath?: string;
  tags?: string;
}

/** Builds WIQL from structured filters only (no raw WIQL from the model); always scoped to one project. */
export function buildWiql(f: SearchFilters): string {
  const c = [`[System.TeamProject] = ${lit(f.project)}`];
  if (f.type) c.push(`[System.WorkItemType] = ${lit(f.type)}`);
  if (f.state) c.push(`[System.State] = ${lit(f.state)}`);
  if (f.assignedTo) c.push(`[System.AssignedTo] = ${f.assignedTo === "@me" ? "@Me" : lit(f.assignedTo)}`);
  if (f.areaPath) c.push(`[System.AreaPath] UNDER ${lit(f.areaPath)}`);
  if (f.tags) c.push(`[System.Tags] CONTAINS ${lit(f.tags)}`);
  if (f.text) c.push(`([System.Title] CONTAINS ${lit(f.text)} OR [System.Description] CONTAINS ${lit(f.text)})`);
  return `SELECT [System.Id] FROM WorkItems WHERE ${c.join(" AND ")} ORDER BY [System.ChangedDate] DESC`;
}
