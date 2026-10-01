import { describe, expect, it } from "vitest";
import { buildWiql, toPatch } from "../src/ado/client.js";
import { Policy, PolicyError } from "../src/policy.js";

describe("buildWiql", () => {
  it("escapes quotes and scopes to project", () => {
    const q = buildWiql({ project: "My'Proj", text: "it's", assignedTo: "@me" });
    expect(q).toContain("[System.TeamProject] = 'My''Proj'");
    expect(q).toContain("CONTAINS 'it''s'");
    expect(q).toContain("[System.AssignedTo] = @Me");
  });
});

describe("toPatch", () => {
  it("drops undefined, keeps null", () => {
    expect(toPatch({ a: 1, b: undefined, c: null })).toEqual([
      { op: "add", path: "/fields/a", value: 1 },
      { op: "add", path: "/fields/c", value: null },
    ]);
  });
});

describe("Policy", () => {
  const p = new Policy({ projects: ["A"], workItemTypes: ["Bug"], operations: ["read"] });
  it("enforces allowlists case-insensitively", () => {
    expect(() => p.project("a")).not.toThrow();
    expect(() => p.project("B")).toThrow(PolicyError);
    expect(() => p.workItemType("Epic")).toThrow(PolicyError);
    expect(() => p.operation("create")).toThrow(PolicyError);
  });
  it("empty lists are unrestricted", () => {
    const open = new Policy({ projects: [], workItemTypes: [], operations: ["read"] });
    expect(open.isProjectAllowed("anything")).toBe(true);
  });
});
