import type { Config, Operation } from "./config.js";

export class PolicyError extends Error {}

const eq = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** Defense in depth on top of ADO's own per-user permissions. Empty list = unrestricted. */
export class Policy {
  constructor(private readonly cfg: Config["policy"]) {}

  operation(op: Operation): void {
    if (!this.cfg.operations.includes(op)) throw new PolicyError(`Operation '${op}' is disabled by gateway policy.`);
  }

  project(name: string): void {
    const { projects } = this.cfg;
    if (projects.length && !projects.some((p) => eq(p, name)))
      throw new PolicyError(`Project '${name}' is not allowed by gateway policy.`);
  }

  workItemType(type: string): void {
    const { workItemTypes } = this.cfg;
    if (workItemTypes.length && !workItemTypes.some((t) => eq(t, type)))
      throw new PolicyError(`Work item type '${type}' is not allowed by gateway policy.`);
  }

  isProjectAllowed(name: string): boolean {
    try {
      this.project(name);
      return true;
    } catch {
      return false;
    }
  }

  isTypeAllowed(type: string): boolean {
    try {
      this.workItemType(type);
      return true;
    } catch {
      return false;
    }
  }

  get allowedProjects(): string[] {
    return this.cfg.projects;
  }
}
