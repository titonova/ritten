import { z } from 'zod';
import { readFile, readdir, lstat, open, rename, unlink, link } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID, createHash } from 'node:crypto';
import { canonical, contained } from '../filesystem.js';
const p = z.string().min(1).max(4096);
const limit = z.number().int().min(1).max(500).default(100);
export const codingDefinitions = {
  'coding.read': {
    schema: z.strictObject({
      path: p,
      start_line: z.number().int().min(1).default(1),
      max_lines: z.number().int().min(1).max(500).default(200),
    }),
    readOnly: true,
    description: 'Read numbered UTF-8 lines from a file',
  },
  'coding.grep': {
    schema: z.strictObject({
      path: p,
      query: z.string().min(1).max(500),
      case_sensitive: z.boolean().default(false),
      max_results: limit,
    }),
    readOnly: true,
    description: 'Search literal text in authorized files with line numbers',
  },
  'coding.glob': {
    schema: z.strictObject({ path: p, pattern: z.string().min(1).max(200), max_results: limit }),
    readOnly: true,
    description: 'Find authorized files by glob pattern relative to the search directory',
  },
  'coding.edit': {
    schema: z.strictObject({
      path: p,
      old_text: z.string().min(1).max(65536),
      new_text: z.string().max(65536),
      replace_all: z.boolean().default(false),
    }),
    readOnly: false,
    description: 'Replace exact text in a file; reject ambiguous or missing matches',
  },
  'coding.write': {
    schema: z.strictObject({
      path: p,
      content: z.string().max(65536),
      create_only: z.boolean().default(true),
    }),
    readOnly: false,
    description: 'Create a text file or explicitly overwrite one',
  },
};
const digest = (s: string) => createHash('sha256').update(s).digest('hex');
async function textFile(p: string) {
  const s = await lstat(p);
  if (!s.isFile() || s.size > 1048576)
    throw Error('File must be a regular text file no larger than 1 MB');
  const b = await readFile(p);
  if (b.includes(0)) throw Error('Binary files are not supported');
  return new TextDecoder('utf-8', { fatal: true }).decode(b);
}
function glob(pattern: string) {
  if (pattern.startsWith('/') || pattern.includes('..') || pattern.includes('\\'))
    throw Error('Invalid glob pattern');
  let out = '^';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        i++;
        if (pattern[i + 1] === '/') {
          i++;
          out += '(?:.*/)?';
        } else out += '.*';
      } else out += '[^/]*';
    } else if (c === '?') out += '[^/]';
    else out += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(out + '$', process.platform === 'win32' ? 'i' : '');
}
export async function codingRun(
  name: string,
  args: Record<string, unknown>,
  signal: AbortSignal,
  authorize: (p: string) => Promise<boolean>,
) {
  const file = String(args.path);
  signal.throwIfAborted();
  if (name === 'coding.read') {
    const data = await textFile(file);
    const lines = data.split(/\r?\n/);
    const start = Number(args.start_line);
    const max = Number(args.max_lines);
    return {
      path: file,
      lines: lines.slice(start - 1, start - 1 + max).map((text, i) => ({ line: start + i, text })),
      truncated: start - 1 + max < lines.length,
      total_lines: lines.length,
    };
  }
  if (name === 'coding.grep' || name === 'coding.glob') {
    const queue = [file];
    const results: unknown[] = [];
    let visited = 0;
    let truncated = false;
    const matcher = name === 'coding.glob' ? glob(String(args.pattern)) : null;
    while (queue.length) {
      signal.throwIfAborted();
      const dir = queue.shift()!;
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        if (++visited > 5000) {
          truncated = true;
          break;
        }
        if (entry.isSymbolicLink()) continue;
        const candidate = path.join(dir, entry.name);
        let resolved: string;
        try {
          resolved = await canonical(candidate);
          if (!contained(file, resolved) || !(await authorize(resolved))) continue;
        } catch {
          continue;
        }
        if (entry.isDirectory()) {
          queue.push(resolved);
          continue;
        }
        if (!entry.isFile()) continue;
        const relative = path.relative(file, resolved).replace(/\\/g, '/');
        if (matcher) {
          if (matcher.test(relative)) results.push({ path: resolved });
        } else {
          let text: string;
          try {
            text = await textFile(resolved);
          } catch {
            continue;
          }
          const needle = String(args.query);
          const q = args.case_sensitive ? needle : needle.toLowerCase();
          for (const [i, line] of text.split(/\r?\n/).entries()) {
            if ((args.case_sensitive ? line : line.toLowerCase()).includes(q)) {
              results.push({ path: resolved, line: i + 1, text: line.slice(0, 2000) });
              if (results.length >= Number(args.max_results)) break;
            }
          }
        }
        if (results.length >= Number(args.max_results)) {
          truncated = true;
          break;
        }
      }
      if (truncated) break;
    }
    return { results, truncated, visited };
  }
  let original: string | null = null;
  try {
    original = await textFile(file);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  let output: string;
  if (name === 'coding.edit') {
    if (original === null) throw Error('File does not exist');
    const old = String(args.old_text);
    const count = original.split(old).length - 1;
    if (!count || (!args.replace_all && count !== 1))
      throw Error('Expected exactly one match unless replace_all is enabled');
    output = args.replace_all
      ? original.split(old).join(String(args.new_text))
      : original.replace(old, () => String(args.new_text));
  } else if (name === 'coding.write') {
    if (args.create_only && original !== null) throw Error('File already exists');
    output = String(args.content);
  } else throw Error('Unknown coding tool');
  const temp = path.join(path.dirname(file), `.ritten-${randomUUID()}.tmp`);
  const h = await open(temp, 'wx', 0o600);
  try {
    await h.writeFile(output);
    await h.sync();
  } finally {
    await h.close();
  }
  try {
    signal.throwIfAborted();
    if (original === null) {
      await link(temp, file);
      await unlink(temp);
    } else {
      const current = await textFile(file);
      if (digest(current) !== digest(original)) throw Error('File changed during edit');
      await rename(temp, file);
    }
  } catch (e) {
    await unlink(temp).catch(() => {});
    throw e;
  }
  return { written: true, sha256: digest(output) };
}
