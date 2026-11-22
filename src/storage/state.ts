import { mkdir, readFile, rename, open, unlink, stat } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
export interface Credential {
  id: string;
  hash: string;
  name: string;
  client: string;
  tools: string[];
  paths: string[];
  domains: string[];
  created: number;
  firstUsed: number | null;
  lastUsed: number | null;
  expires: number;
  revoked: boolean;
  kind: 'bearer' | 'access' | 'refresh';
  family: string;
}
export interface Approval {
  id: string;
  kind: 'tool' | 'oauth';
  client: string;
  tool: string;
  arguments: unknown;
  binding: string;
  expires: number;
  status: 'pending' | 'approved' | 'denied' | 'consumed';
}
export interface OAuthClient {
  id: string;
  name: string;
  redirects: string[];
  revoked: boolean;
}
export interface Authorization {
  id: string;
  client: string;
  redirect: string;
  challenge: string;
  state: string;
  scope: string;
  resource: string;
  expires: number;
  approval: string;
  codeHash: string | null;
  used: boolean;
}
export interface State {
  version: 1;
  paused: boolean;
  panic: boolean;
  credentials: Credential[];
  approvals: Approval[];
  clients: OAuthClient[];
  authorizations: Authorization[];
  dedup: Record<
    string,
    { binding: string; status: 'pending' | 'complete'; result?: unknown; at: number }
  >;
  rawShellEnabled: boolean;
  ownerSessionTimeoutMs: 900000 | 3600000 | 86400000;
}
export const emptyState = (): State => ({
  version: 1,
  paused: false,
  panic: false,
  credentials: [],
  approvals: [],
  clients: [],
  authorizations: [],
  dedup: {},
  rawShellEnabled: false,
  ownerSessionTimeoutMs: 900000,
});
const text = z.string();
const time = z.number().finite().nonnegative();
const stateSchema = z.strictObject({
  version: z.literal(1),
  paused: z.boolean(),
  panic: z.boolean(),
  rawShellEnabled: z.boolean(),
  ownerSessionTimeoutMs: z
    .union([z.literal(900000), z.literal(3600000), z.literal(86400000)])
    .default(900000),
  credentials: z
    .array(
      z.strictObject({
        id: text,
        hash: text.regex(/^[a-f0-9]{64}$/),
        name: text,
        client: text,
        tools: z.array(text),
        paths: z.array(text),
        domains: z.array(text),
        created: time,
        firstUsed: time.nullable(),
        lastUsed: time.nullable(),
        expires: time,
        revoked: z.boolean(),
        kind: z.enum(['bearer', 'access', 'refresh']),
        family: text,
      }),
    )
    .max(100000),
  approvals: z
    .array(
      z.strictObject({
        id: text,
        kind: z.enum(['tool', 'oauth']),
        client: text,
        tool: text,
        arguments: z.unknown(),
        binding: text,
        expires: time,
        status: z.enum(['pending', 'approved', 'denied', 'consumed']),
      }),
    )
    .max(20000),
  clients: z
    .array(z.strictObject({ id: text, name: text, redirects: z.array(text), revoked: z.boolean() }))
    .max(1000),
  authorizations: z
    .array(
      z.strictObject({
        id: text,
        client: text,
        redirect: text,
        challenge: text,
        state: text,
        scope: text,
        resource: text,
        expires: time,
        approval: text,
        codeHash: text.nullable(),
        used: z.boolean(),
      }),
    )
    .max(10000),
  dedup: z.record(
    text,
    z.strictObject({
      binding: text,
      status: z.enum(['pending', 'complete']),
      result: z.unknown().optional(),
      at: time,
    }),
  ),
});
export async function atomicWrite(filename: string, content: string): Promise<void> {
  await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  const temp = `${filename}.${randomUUID()}.tmp`;
  const handle = await open(temp, 'wx', 0o600);
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temp, filename);
  } catch (e) {
    await unlink(temp).catch(() => {});
    throw e;
  }
}
export class StateStore {
  private queue: Promise<unknown> = Promise.resolve();
  constructor(
    readonly filename: string,
    private state: State,
  ) {}
  static async load(filename: string): Promise<StateStore> {
    let state: State;
    try {
      if ((await stat(filename)).size > 67108864) throw new Error('State exceeds 64MB limit');
      state = stateSchema.parse(JSON.parse(await readFile(filename, 'utf8'))) as State;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
      state = emptyState();
    }
    if (
      state.version !== 1 ||
      !Array.isArray(state.credentials) ||
      !Array.isArray(state.approvals) ||
      typeof state.dedup !== 'object'
    )
      throw new Error('Invalid state; refusing to start');
    return new StateStore(filename, state);
  }
  snapshot(): State {
    return structuredClone(this.state);
  }
  async change<T>(fn: (s: State) => T): Promise<T> {
    const op = this.queue.then(async () => {
      const next = structuredClone(this.state);
      const value = fn(next);
      const encoded = JSON.stringify(next);
      if (Buffer.byteLength(encoded) > 67108864) throw new Error('State exceeds 64MB limit');
      await atomicWrite(this.filename, encoded);
      this.state = structuredClone(next);
      return value;
    });
    this.queue = op.catch(() => {});
    return op;
  }
}
export async function acquireLock(directory: string): Promise<() => Promise<void>> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const filename = path.join(directory, 'instance.lock');
  const handle = await open(filename, 'wx', 0o600).catch(() => {
    throw new Error(
      'Data directory locked. Stop the other instance; after a crash verify it has exited before removing instance.lock.',
    );
  });
  await handle.writeFile(String(process.pid));
  return async () => {
    await handle.close();
    await unlink(filename);
  };
}
