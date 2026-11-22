import path from 'node:path';
import type { Config } from '../../config/schema.js';
import type { Credential } from '../../storage/state.js';
import { evaluatePolicy, matches } from '../../policy/engine.js';
import { authorizePath, normalized } from '../filesystem.js';
import { resolveExecutable } from './run.js';

type Decision = 'allow' | 'ask';
interface ExecutablePermission {
  path: string;
  decision: Decision;
  working_directories: string[];
}
interface TaskPermission {
  name: string;
  executable: string;
  args: string[];
  cwd: string;
  decision: Decision;
}

const foldCase = process.platform === 'win32';
const same = (a: string, b: string): boolean =>
  foldCase ? a.toLowerCase() === b.toLowerCase() : a === b;
const hasGlob = (value: string): boolean => /[*?]/.test(value);

function hasToolScope(credential: Credential, tool: string): boolean {
  return credential.tools.some((pattern) => matches(pattern, tool));
}

function winningDecision(
  config: Config,
  credential: Credential,
  tool: string,
  executable: string,
  cwd: string,
  task?: string,
): Decision | null {
  const result = evaluatePolicy(config.policy, {
    tool,
    client: credential.client,
    paths: [cwd],
    executables: [executable],
    ...(task ? { tasks: [task] } : {}),
  });
  if (result.decision === 'deny' || !result.ruleId) return null;
  const rule = config.policy.rules.find((candidate) => candidate.id === result.ruleId);
  if (
    !rule?.match.executables?.some((pattern) => matches(pattern, executable, foldCase)) ||
    (task !== undefined && !rule.match.tasks?.includes(task))
  )
    return null;
  return result.decision;
}

function relevantPathRulesAreUniform(
  config: Config,
  credential: Credential,
  executable: string,
  root: string,
): boolean {
  const rootPrefix = `${root.replace(/\/$/, '')}/`;
  for (const rule of config.policy.rules) {
    if (!rule.match.tools.some((pattern) => matches(pattern, 'process.run'))) continue;
    if (rule.match.clients && !rule.match.clients.includes(credential.client)) continue;
    if (
      !rule.match.executables?.some((pattern) => matches(pattern, executable, foldCase)) ||
      rule.match.tasks ||
      rule.match.commands ||
      rule.match.domains ||
      !rule.match.paths
    )
      continue;
    for (const rawPattern of rule.match.paths) {
      const pattern = normalized(rawPattern);
      if (same(pattern, root) || same(pattern, `${root}/**`)) continue;
      if (!hasGlob(pattern)) {
        if (
          same(pattern, rootPrefix.slice(0, -1)) ||
          pattern.toLowerCase().startsWith(rootPrefix.toLowerCase())
        )
          return false;
        continue;
      }
      const wildcard = pattern.search(/[*?]/);
      const fixed = pattern.slice(0, wildcard).replace(/\/$/, '');
      const p = foldCase ? fixed.toLowerCase() : fixed;
      const r = foldCase ? root.toLowerCase() : root;
      if (!fixed || p === r || p.startsWith(`${r}/`) || r.startsWith(`${p}/`)) return false;
    }
  }
  return true;
}

function credentialDirectoryScopes(credential: Credential, root: string): string[] {
  const result: string[] = [];
  if (credential.paths.some((pattern) => matches(pattern, root, foldCase))) result.push(root);
  if (credential.paths.some((pattern) => same(normalized(pattern), `${root}/**`)))
    result.push(`${root}/**`);
  return result;
}

async function effectiveExecutablePaths(config: Config): Promise<string[]> {
  const candidates = new Set<string>();
  for (const rule of config.policy.rules) {
    if (!rule.match.tools.some((pattern) => matches(pattern, 'process.run'))) continue;
    for (const configuredPath of rule.match.executables ?? []) {
      if (hasGlob(configuredPath) || !path.isAbsolute(configuredPath)) continue;
      try {
        const canonical = normalized(await resolveExecutable(configuredPath));
        if (matches(configuredPath, canonical, foldCase)) candidates.add(canonical);
      } catch {
        // Unresolvable or unsupported executables cannot be effective permissions.
      }
    }
  }
  return [...candidates];
}

/** Return only process permissions that can be established for this credential. */
export async function listAllowedProcess(
  config: Config,
  credential: Credential,
): Promise<{ executables: ExecutablePermission[]; tasks: TaskPermission[] }> {
  if (!config.toolsets.enabled.includes('process')) return { executables: [], tasks: [] };

  const roots: string[] = [];
  for (const configuredRoot of config.toolsets.settings.filesystem.roots) {
    try {
      roots.push(normalized(await authorizePath(config, configuredRoot.path, false)));
    } catch {
      // Skip roots that no longer resolve to an authorized directory.
    }
  }

  const executablePermissions: ExecutablePermission[] = [];
  if (hasToolScope(credential, 'process.run')) {
    for (const executable of await effectiveExecutablePaths(config)) {
      const byDecision = new Map<Decision, Set<string>>();
      for (const root of roots) {
        const credentialScopes = credentialDirectoryScopes(credential, root);
        for (const scope of credentialScopes) {
          if (scope === root) {
            const decision = winningDecision(config, credential, 'process.run', executable, root);
            if (decision) {
              const directories = byDecision.get(decision) ?? new Set<string>();
              directories.add(root);
              byDecision.set(decision, directories);
            }
          } else if (relevantPathRulesAreUniform(config, credential, executable, root)) {
            const probe = `${root}/.ritten-permission-probe`;
            const childProbe = `${probe}/nested`;
            const decision = winningDecision(config, credential, 'process.run', executable, probe);
            if (
              decision &&
              winningDecision(config, credential, 'process.run', executable, childProbe) ===
                decision
            ) {
              const directories = byDecision.get(decision) ?? new Set<string>();
              directories.add(scope);
              byDecision.set(decision, directories);
            }
          }
        }
      }
      for (const [decision, workingDirectories] of byDecision)
        executablePermissions.push({
          path: executable,
          decision,
          working_directories: [...workingDirectories],
        });
    }
  }

  const tasks: TaskPermission[] = [];
  if (hasToolScope(credential, 'process.run_task')) {
    for (const [name, task] of Object.entries(config.toolsets.settings.process.tasks)) {
      try {
        const cwd = normalized(await authorizePath(config, task.cwd, false));
        if (!credential.paths.some((pattern) => matches(pattern, cwd, foldCase))) continue;
        const executable = normalized(await resolveExecutable(task.executable));
        const decision = winningDecision(
          config,
          credential,
          'process.run_task',
          executable,
          cwd,
          name,
        );
        if (decision)
          tasks.push({
            name,
            executable,
            args: [...task.args],
            cwd,
            decision,
          });
      } catch {
        // Invalid paths, missing executables, and out-of-scope tasks are omitted.
      }
    }
  }

  return { executables: executablePermissions, tasks };
}
