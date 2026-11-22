import { readdir, readFile, lstat } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import { hash } from '../auth/credentials.js';
import type { ToolDefinition } from '../toolkit/index.js';
import { parse } from 'yaml';

export interface LoadedTool {
  name: string;
  definition: ToolDefinition;
  fingerprint: string;
}
export const reserved = new Set(['ritten', 'filesystem', 'coding', 'web', 'raw_shell', 'process']);
const valid = /^[a-zA-Z0-9][a-zA-Z0-9_-]*$/;
export async function discover(directories: string[]): Promise<Map<string, string>> {
  const found = new Map<string, string>();
  for (const directory of directories) {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') continue;
      throw e;
    }
    for (const entry of entries) {
      if (
        !entry.isDirectory() ||
        entry.isSymbolicLink() ||
        !valid.test(entry.name) ||
        reserved.has(entry.name)
      )
        continue;
      if (found.has(entry.name)) {
        console.warn(`Duplicate toolset ${entry.name}: keeping first directory`);
        continue;
      }
      found.set(entry.name, path.join(directory, entry.name));
    }
  }
  return found;
}
async function fingerprint(directory: string): Promise<string> {
  let total = 0;
  let count = 0;
  const parts: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
      if (++count > 500) throw new Error('Toolset exceeds fingerprint file limit');
      const filename = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) throw new Error('Toolset symlinks are unsupported');
      if (entry.isDirectory()) await walk(filename);
      else {
        const size = (await lstat(filename)).size;
        total += size;
        if (total > 5242880) throw new Error('Toolset exceeds fingerprint byte limit');
        parts.push(
          path.relative(directory, filename),
          hash((await readFile(filename)).toString('base64')),
        );
      }
    }
  };
  await walk(directory);
  return hash(JSON.stringify(parts));
}
export async function loadCustom(directories: string[], enabled: string[]): Promise<LoadedTool[]> {
  const available = await discover(directories);
  const result: LoadedTool[] = [];
  for (const name of enabled.filter((n) => !reserved.has(n))) {
    const directory = available.get(name);
    if (!directory) throw new Error(`Enabled toolset not found: ${name}`);
    const digest = await fingerprint(directory);
    try {
      const content = await readFile(path.join(directory, 'toolset.yaml'), 'utf8');
      z.strictObject({
        description: z.string().optional(),
        required_scopes: z.array(z.string()).optional(),
        suggested_policy: z.record(z.string(), z.enum(['allow', 'ask', 'deny'])).optional(),
      }).parse(parse(content, { uniqueKeys: true, maxAliasCount: 20 }));
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      if (entry.name === 'node_modules') continue;
      const filename = entry.isDirectory()
        ? path.join(directory, entry.name, 'index.ts')
        : path.join(directory, entry.name);
      let actual = filename;
      if (entry.isDirectory()) {
        try {
          await lstat(actual);
        } catch {
          actual = path.join(directory, entry.name, 'index.js');
          try {
            await lstat(actual);
          } catch {
            continue;
          }
        }
      }
      const tool = entry.isDirectory() ? entry.name : entry.name.replace(/\.(?:ts|js)$/, '');
      if (
        !valid.test(tool) ||
        entry.name.startsWith('_') ||
        (!entry.isDirectory() && !/\.(?:ts|js)$/.test(entry.name))
      )
        continue;
      if (result.some((t) => t.name === `${name}.${tool}`))
        throw new Error(`Duplicate tool: ${name}.${tool}`);
      const { tsImport } = await import('tsx/esm/api');
      const mod = (await tsImport(pathToFileURL(actual).href, import.meta.url)) as {
        default?: ToolDefinition;
      };
      const definition = mod.default;
      if (
        !definition ||
        typeof definition.run !== 'function' ||
        typeof definition.description !== 'string' ||
        !(definition.inputSchema instanceof z.ZodType)
      )
        throw new Error(`Invalid tool definition: ${name}.${tool}`);
      if (z.toJSONSchema(definition.inputSchema).type !== 'object')
        throw new Error(`Tool input schema must describe an object: ${name}.${tool}`);
      result.push({ name: `${name}.${tool}`, definition, fingerprint: digest });
    }
  }
  return result;
}
