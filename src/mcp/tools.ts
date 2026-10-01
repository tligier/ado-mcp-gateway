import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { AdoClient, AdoError, buildWiql, toPatch, type WorkItem } from "../ado/client.js";
import type { Config } from "../config.js";
import { Policy, PolicyError } from "../policy.js";

export interface UserCtx {
  sessionId: string;
  upn?: string;
}
export interface Deps {
  cfg: Config;
  policy: Policy;
  getToken: (sessionId: string) => Promise<string>;
}

const SUMMARY_FIELDS = [
  "System.Title", "System.WorkItemType", "System.State", "System.AssignedTo", "System.TeamProject",
  "System.AreaPath", "System.IterationPath", "Microsoft.VSTS.Common.Priority", "System.Tags",
  "System.CreatedBy", "System.ChangedBy", "System.ChangedDate",
];

const summarize = (w: WorkItem, org: string) => ({
  id: w.id,
  rev: w.rev,
  url: `https://dev.azure.com/${org}/${encodeURIComponent(String(w.fields["System.TeamProject"] ?? ""))}/_workitems/edit/${w.id}`,
  fields: w.fields,
});

const text = (v: unknown) => ({ content: [{ type: "text" as const, text: typeof v === "string" ? v : JSON.stringify(v, null, 2) }] });
const fail = (msg: string) => ({ isError: true, content: [{ type: "text" as const, text: msg }] });

export function createMcpServer(deps: Deps): McpServer {
  const { cfg, policy } = deps;
  const server = new McpServer({ name: "ado-mcp-gateway", version: "0.1.0" });

  /** Wraps a tool: resolves the caller's delegated token, enforces policy, audits, maps errors. */
  const tool = <S extends z.ZodRawShape>(
    name: string,
    title: string,
    description: string,
    op: "read" | "create" | "update",
    shape: S,
    run: (a: z.infer<z.ZodObject<S>>, ado: AdoClient) => Promise<unknown>,
  ) =>
    (server as any).registerTool(
      name,
      { title, description, inputSchema: shape, annotations: { readOnlyHint: op === "read", destructiveHint: false, openWorldHint: false } },
      async (args: any, extra: any) => {
        const user = extra.authInfo?.extra as { sessionId?: string; user?: { upn?: string } } | undefined;
        if (!user?.sessionId) return fail("Not authenticated.");
        try {
          policy.operation(op);
          const ado = new AdoClient(cfg.adoOrg, await deps.getToken(user.sessionId));
          console.log(JSON.stringify({ audit: name, user: user.user?.upn, project: args.project, id: args.id }));
          return text(await run(args, ado));
        } catch (e) {
          if (e instanceof PolicyError || e instanceof AdoError) return fail(e.message);
          console.error(name, e);
          return fail(e instanceof Error ? e.message : "Unexpected error");
        }
      },
    );

  /** Fetches an item and verifies it is inside policy before it is returned or modified. */
  const guarded = async (ado: AdoClient, id: number) => {
    const w = await ado.getWorkItem(id, { fields: ["System.TeamProject", "System.WorkItemType"] });
    policy.project(String(w.fields["System.TeamProject"]));
    policy.workItemType(String(w.fields["System.WorkItemType"]));
  };

  tool("ado_get_projects", "List projects", "List Azure DevOps projects the signed-in user can see (filtered by gateway policy).", "read", {}, async (_a, ado) =>
    (await ado.listProjects()).value.filter((p) => policy.isProjectAllowed(p.name)).map((p) => ({ name: p.name, description: p.description, state: p.state })),
  );

  tool("ado_get_work_item_types", "List work item types", "List work item types available in a project.", "read",
    { project: z.string() },
    async ({ project }, ado) => {
      policy.project(project);
      return (await ado.getWorkItemTypes(project)).value
        .filter((t) => policy.isTypeAllowed(t.name))
        .map((t) => ({ name: t.name, description: t.description }));
    });

  tool("ado_get_work_item", "Get work item", "Get a work item by id, optionally with all fields and relations.", "read",
    { id: z.number().int().positive(), includeAllFields: z.boolean().default(false) },
    async ({ id, includeAllFields }, ado) => {
      const w = await ado.getWorkItem(id, { expandRelations: true });
      policy.project(String(w.fields["System.TeamProject"]));
      policy.workItemType(String(w.fields["System.WorkItemType"]));
      if (includeAllFields) return { ...summarize(w, cfg.adoOrg), relations: w.relations };
      const picked = Object.fromEntries([...SUMMARY_FIELDS, "System.Description", "Microsoft.VSTS.TCM.ReproSteps", "Microsoft.VSTS.Common.AcceptanceCriteria"].filter((k) => k in w.fields).map((k) => [k, w.fields[k]]));
      return { ...summarize({ ...w, fields: picked }, cfg.adoOrg), relations: w.relations };
    });

  tool("ado_search_work_items", "Search work items", "Search work items in one project using structured filters. Use assignedTo='@me' for the caller's items.", "read",
    {
      project: z.string(),
      text: z.string().optional().describe("Matches title or description"),
      type: z.string().optional(),
      state: z.string().optional(),
      assignedTo: z.string().optional(),
      areaPath: z.string().optional(),
      tags: z.string().optional(),
      top: z.number().int().min(1).max(50).default(20),
    },
    async ({ top, ...f }, ado) => {
      policy.project(f.project);
      if (f.type) policy.workItemType(f.type);
      const ids = await ado.queryWiql(f.project, buildWiql(f), top);
      const items = await ado.getWorkItemsBatch(ids, SUMMARY_FIELDS);
      return { count: items.length, items: items.filter((w) => policy.isTypeAllowed(String(w.fields["System.WorkItemType"]))).map((w) => summarize(w, cfg.adoOrg)) };
    });

  const writable = {
    title: z.string().min(1).max(255),
    description: z.string().optional().describe("HTML is accepted by Azure DevOps"),
    priority: z.number().int().min(1).max(4).optional(),
    assignedTo: z.string().optional().describe("Display name or email of the assignee"),
    areaPath: z.string().optional(),
    iterationPath: z.string().optional(),
    tags: z.string().optional().describe("Semicolon separated"),
    fields: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])).optional()
      .describe("Extra fields by reference name, e.g. {\"Microsoft.VSTS.Common.Severity\":\"2 - High\"}"),
  };
  const fieldMap = (a: Partial<Record<keyof typeof writable, any>>) => ({
    "System.Title": a.title,
    "System.Description": a.description,
    "Microsoft.VSTS.Common.Priority": a.priority,
    "System.AssignedTo": a.assignedTo,
    "System.AreaPath": a.areaPath,
    "System.IterationPath": a.iterationPath,
    "System.Tags": a.tags,
    ...(a.fields ?? {}),
  });

  tool("ado_create_work_item", "Create work item", "Create a work item. It is created as the signed-in user.", "create",
    { project: z.string(), type: z.string(), ...writable },
    async (a, ado) => {
      policy.project(a.project);
      policy.workItemType(a.type);
      const w = await ado.createWorkItem(a.project, a.type, toPatch(fieldMap(a)));
      return summarize(w, cfg.adoOrg);
    });

  tool("ado_update_work_item", "Update work item", "Update fields of an existing work item as the signed-in user. Only supplied fields change.", "update",
    {
      id: z.number().int().positive(),
      ...Object.fromEntries(Object.entries(writable).map(([k, v]) => [k, v.optional()])) as { [K in keyof typeof writable]: z.ZodOptional<(typeof writable)[K]> },
      state: z.string().optional(),
      comment: z.string().optional().describe("Added to the discussion/history"),
    },
    async ({ id, state, comment, ...rest }, ado) => {
      await guarded(ado, id);
      const ops = toPatch({ ...fieldMap(rest), "System.State": state, "System.History": comment });
      if (!ops.length) throw new PolicyError("Nothing to update.");
      return summarize(await ado.updateWorkItem(id, ops), cfg.adoOrg);
    });

  return server;
}
