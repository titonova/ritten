import { lstat, realpath, open, readdir, rename, mkdir, unlink, rmdir } from 'node:fs/promises';
import path from 'node:path';
import { constants } from 'node:fs';
import { randomUUID } from 'node:crypto';
import type { Config } from '../config/schema.js';

export function contained(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return (
    relative === '' ||
    (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative))
  );
}
export const normalized = (p: string) => p.replace(/\\/g, '/');
export async function canonical(input: string, destination = false): Promise<string> {
  if (
    !path.isAbsolute(input) ||
    input.includes('\0') ||
    /[\*?]/.test(input) ||
    (process.platform === 'win32' &&
      (/^\\\\/.test(input) ||
        input.slice(2).includes(':') ||
        /(?:^|[\\/])(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|[\\/]|$)/i.test(input) ||
        /[ .](?:[\\/]|$)/.test(input)))
  )
    throw new Error('Unsupported path');
  const absolute = path.resolve(input);
  let cursor = path.parse(absolute).root;
  const parts = absolute.slice(cursor.length).split(path.sep).filter(Boolean);
  for (let i = 0; i < parts.length; i++) {
    cursor = path.join(cursor, parts[i]!);
    try {
      if ((await lstat(cursor)).isSymbolicLink())
        throw new Error('Symlinks and junctions are disabled');
    } catch (e) {
      if (destination && i === parts.length - 1 && (e as NodeJS.ErrnoException).code === 'ENOENT')
        return path.join(await realpath(path.dirname(cursor)), path.basename(cursor));
      throw e;
    }
  }
  return realpath(absolute);
}
export async function authorizePath(
  config: Config,
  input: string,
  write: boolean,
  destination = false,
): Promise<string> {
  const target = await canonical(input, destination);
  for (const root of config.toolsets.settings.filesystem.roots) {
    if (write && root.access !== 'read-write') continue;
    const resolved = await canonical(root.path);
    if (contained(resolved, target) && (!write || resolved !== target)) return target;
  }
  throw new Error('Path is outside configured roots or access mode');
}
export async function readChunk(
  filename: string,
  offset: number,
  length: number,
): Promise<unknown> {
  const handle = await open(filename, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error('Not a regular file');
    const buffer = Buffer.alloc(length);
    const result = await handle.read(buffer, 0, length, offset);
    return {
      text: buffer.subarray(0, result.bytesRead).toString('utf8'),
      offset,
      returnedBytes: result.bytesRead,
      size: stat.size,
      continuation:
        offset + result.bytesRead < stat.size ? { offset: offset + result.bytesRead } : null,
    };
  } finally {
    await handle.close();
  }
}
export async function filesystemRun(
  tool: string,
  args: Record<string, unknown>,
  signal: AbortSignal,
): Promise<unknown> {
  signal.throwIfAborted();
  const filename = String(args.path);
  if (tool === 'read_file')
    return readChunk(filename, Number(args.offset ?? 0), Number(args.length ?? 16384));
  if (tool === 'stat') {
    const s = await lstat(filename);
    return {
      size: s.size,
      directory: s.isDirectory(),
      file: s.isFile(),
      modified: s.mtime.toISOString(),
    };
  }
  if (tool === 'list_directory') {
    const entries = await readdir(filename, { withFileTypes: true });
    const offset = Number(args.offset ?? 0);
    return {
      entries: entries
        .slice(offset, offset + 200)
        .map((e) => ({ name: e.name, directory: e.isDirectory(), symlink: e.isSymbolicLink() })),
      continuation: offset + 200 < entries.length ? { offset: offset + 200 } : null,
    };
  }
  if (tool === 'search') {
    const query = String(args.query);
    const results: string[] = [];
    const queue = [filename];
    let visited = 0;
    while (queue.length && results.length < 100 && visited < 5000) {
      signal.throwIfAborted();
      const dir = await canonical(queue.shift()!);
      if (!contained(filename, dir)) throw new Error('Search escaped its root');
      for (const e of await readdir(dir, { withFileTypes: true })) {
        if (++visited > 5000) break;
        if (e.isSymbolicLink()) continue;
        const candidate = path.join(dir, e.name);
        if (e.name.includes(query)) results.push(candidate);
        if (e.isDirectory()) queue.push(candidate);
        if (results.length >= 100) break;
      }
    }
    return {
      paths: results,
      truncated: queue.length > 0 || visited >= 5000 || results.length >= 100,
    };
  }
  if (tool === 'write_file') {
    const temp = path.join(path.dirname(filename), `.ritten-${randomUUID()}.tmp`);
    const handle = await open(temp, 'wx', 0o600);
    try {
      await handle.writeFile(String(args.content));
      await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      signal.throwIfAborted();
      await rename(temp, filename);
    } catch (e) {
      await unlink(temp).catch(() => {});
      throw e;
    }
    return { written: true };
  }
  if (tool === 'create_directory') {
    await mkdir(filename);
    return { created: true };
  }
  if (tool === 'move') {
    try {
      await lstat(String(args.destination));
      throw new Error('Destination already exists');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    }
    await rename(filename, String(args.destination));
    return { moved: true };
  }
  if (tool === 'delete') {
    const s = await lstat(filename);
    if (s.isDirectory()) await rmdir(filename);
    else await unlink(filename);
    return { deleted: true };
  }
  throw new Error('Unknown filesystem tool');
}
