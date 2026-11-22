import type { Config } from '../config/schema.js';

export interface PolicyRequest {
  tool: string;
  client: string;
  paths?: string[];
  domains?: string[];
  commands?: string[];
  executables?: string[];
  tasks?: string[];
}
export interface PolicyDecision {
  decision: 'allow' | 'ask' | 'deny';
  ruleId?: string;
}

export function matches(pattern: string, value: string, foldCase = false): boolean {
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '\u0000')
    .replace(/\*/g, '[^/]*')
    .replace(/\u0000/g, '.*');
  return new RegExp(`^${escaped}$`, foldCase ? 'i' : '').test(value);
}

/** Ordered deterministic policy; canonical resource resolution belongs to the executor. */
export function evaluatePolicy(
  policy: Pick<Config['policy'], 'rules' | 'default'>,
  request: PolicyRequest,
): PolicyDecision {
  for (const rule of policy.rules) {
    if (!rule.match.tools.some((pattern) => matches(pattern, request.tool))) continue;
    if (rule.match.clients && !rule.match.clients.includes(request.client)) continue;
    if (
      rule.match.paths &&
      (!request.paths?.length ||
        !(rule.decision === 'deny'
          ? request.paths.some((p) =>
              rule.match.paths!.some((pattern) =>
                matches(pattern, p, process.platform === 'win32'),
              ),
            )
          : request.paths.every((p) =>
              rule.match.paths!.some((pattern) =>
                matches(pattern, p, process.platform === 'win32'),
              ),
            )))
    )
      continue;
    if (
      rule.match.domains &&
      (!request.domains?.length || !request.domains.every((d) => rule.match.domains!.includes(d)))
    )
      continue;
    if (
      rule.match.commands &&
      (!request.commands?.length ||
        !request.commands.every((c) => rule.match.commands!.includes(c)))
    )
      continue;
    if (
      rule.match.executables &&
      (!request.executables?.length ||
        !request.executables.every((x) =>
          rule.match.executables!.some((p) => matches(p, x, process.platform === 'win32')),
        ))
    )
      continue;
    if (
      rule.match.tasks &&
      (!request.tasks?.length || !request.tasks.every((x) => rule.match.tasks!.includes(x)))
    )
      continue;
    return { decision: rule.decision, ruleId: rule.id };
  }
  return { decision: 'deny' };
}
