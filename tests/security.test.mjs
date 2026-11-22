import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from 'node:net';
import { configSchema } from '../dist/config/schema.js';
import { StateStore } from '../dist/storage/state.js';
import {
  issueCredential,
  authenticate,
  passwordHash,
  passwordMatches,
  hash,
  credentialIsLive,
} from '../dist/auth/credentials.js';
import { AuditLog, redact } from '../dist/audit/log.js';
import { Executor } from '../dist/executor/pipeline.js';
import { startServer } from '../dist/server/http.js';
import { canonical } from '../dist/toolsets/filesystem.js';
import { evaluatePolicy } from '../dist/policy/engine.js';
import { webFetch } from '../dist/toolsets/web.js';
import { runShell } from '../dist/toolsets/shell.js';

async function port() {
  const s = createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const p = s.address().port;
  await new Promise((r) => s.close(r));
  return p;
}
async function fixture() {
  const dir = await mkdtemp(path.join(tmpdir(), 'ritten-security-'));
  const root = path.join(dir, 'root');
  await mkdir(root);
  await writeFile(path.join(root, 'file.txt'), 'hello');
  const config = configSchema.parse({
    version: 1,
    server: { host: '127.0.0.1', port: await port(), owner_port: await port() },
    toolsets: {
      enabled: ['ritten', 'filesystem'],
      settings: { filesystem: { roots: [{ path: root, access: 'read-write' }] } },
    },
    policy: {
      default: 'deny',
      approval_timeout: '1s',
      rules: [
        { id: 'health', match: { tools: ['ritten.health'] }, decision: 'allow' },
        {
          id: 'read',
          match: {
            tools: [
              'filesystem.read_file',
              'filesystem.stat',
              'filesystem.list_directory',
              'filesystem.search',
            ],
            paths: [root.replaceAll('\\', '/') + '/**'],
          },
          decision: 'allow',
        },
        {
          id: 'write',
          match: { tools: ['filesystem.write_file'], paths: [root.replaceAll('\\', '/') + '/**'] },
          decision: 'ask',
        },
      ],
    },
  });
  const store = await StateStore.load(path.join(dir, 'state.json'));
  const audit = new AuditLog(path.join(dir, 'logs'), config.logging);
  const executor = new Executor(config, store, audit);
  const { token, credential } = await issueCredential(store, {
    name: 'test',
    client: 'test',
    kind: 'bearer',
    tools: ['*'],
    paths: [root.replaceAll('\\', '/') + '/**'],
    domains: [],
  });
  return {
    dir,
    root,
    config,
    store,
    audit,
    executor,
    token,
    credential,
    async cleanup() {
      await rm(dir, { recursive: true, force: true });
    },
  };
}
test('filesystem scopes, approvals, durable deduplication, and revocation', async () => {
  const f = await fixture();
  try {
    const result = await f.executor.call(
      'filesystem.read_file',
      { path: path.join(f.root, 'file.txt') },
      f.credential,
      'read',
    );
    assert.equal(result.text, 'hello');
    await assert.rejects(
      f.executor.call(
        'filesystem.read_file',
        { path: path.join(f.dir, 'state.json') },
        f.credential,
        'escape',
      ),
      /outside/,
    );
    const file = path.join(f.root, 'new.txt');
    const write = f.executor.call(
      'filesystem.write_file',
      { path: file, content: 'approved' },
      f.credential,
      'write-1',
    );
    let approval;
    for (let i = 0; i < 50; i++) {
      approval = f.store.snapshot().approvals.find((a) => a.status === 'pending');
      if (approval) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(approval);
    assert.equal(approval.arguments.content, 'approved');
    await f.store.change((s) => {
      s.approvals.find((a) => a.id === approval.id).status = 'approved';
    });
    await write;
    assert.equal(await readFile(file, 'utf8'), 'approved');
    await writeFile(file, 'externally changed');
    await f.executor.call(
      'filesystem.write_file',
      { path: file, content: 'approved' },
      f.credential,
      'write-1',
    );
    assert.equal(await readFile(file, 'utf8'), 'externally changed');
    await assert.rejects(
      f.executor.call(
        'filesystem.write_file',
        { path: file, content: 'changed' },
        f.credential,
        'write-1',
      ),
      /Identifier reused/,
    );
    const reload = await StateStore.load(f.store.filename);
    assert.equal(Object.values(reload.snapshot().dedup)[0].status, 'complete');
    await f.store.change((s) => {
      s.credentials[0].revoked = true;
    });
    await assert.rejects(authenticate(f.store, f.token), /Unauthorized/);
  } finally {
    await f.cleanup();
  }
});
test('approval timeout denies execution', async () => {
  const f = await fixture();
  try {
    await assert.rejects(
      f.executor.call(
        'filesystem.write_file',
        { path: path.join(f.root, 'file.txt'), content: 'bad' },
        f.credential,
        'timeout',
      ),
      /timed out/,
    );
    assert.equal(await readFile(path.join(f.root, 'file.txt'), 'utf8'), 'hello');
  } finally {
    await f.cleanup();
  }
});
test('junction escapes are rejected', async () => {
  const f = await fixture();
  try {
    await symlink(
      f.dir,
      path.join(f.root, 'escape'),
      process.platform === 'win32' ? 'junction' : 'dir',
    );
    await assert.rejects(canonical(path.join(f.root, 'escape', 'state.json')), /Symlinks/);
  } finally {
    await f.cleanup();
  }
});
test('audit redacts nested secrets and bearer values', () => {
  const r = redact({
    nested: { password: 'sensitive' },
    authorization: 'Bearer abc',
    text: 'Bearer secret',
  });
  assert.equal(r.nested.password, '[REDACTED]');
  assert.equal(r.authorization, '[REDACTED]');
  assert.doesNotMatch(JSON.stringify(r), /sensitive|secret/);
});
test('passphrase verifier is salted and rejects incorrect passphrases', () => {
  const first = passwordHash('a strong test passphrase');
  const second = passwordHash('a strong test passphrase');
  assert.notEqual(first, second);
  assert.equal(passwordMatches('a strong test passphrase', first), true);
  assert.equal(passwordMatches('incorrect', first), false);
});
test('bearer unused, shelf, idle and revocation boundaries', async () => {
  const f = await fixture();
  try {
    const c = { ...f.credential, created: 0, expires: 200000000, firstUsed: null, lastUsed: null };
    assert.equal(credentialIsLive(c, 86399999), true);
    assert.equal(credentialIsLive(c, 86400000), false);
    c.firstUsed = 50000000;
    c.lastUsed = 136399999;
    assert.equal(credentialIsLive(c, 136400000), false);
    c.firstUsed = 100000000;
    c.lastUsed = 100000000;
    assert.equal(credentialIsLive(c, 103599999), true);
    assert.equal(credentialIsLive(c, 103600000), false);
    c.revoked = true;
    assert.equal(credentialIsLive(c, 100000001), false);
  } finally {
    await f.cleanup();
  }
});
test('multi-resource deny matches either move endpoint', () => {
  const p = {
    default: 'deny',
    rules: [
      {
        id: 'sensitive',
        match: { tools: ['filesystem.move'], paths: ['**/.env'] },
        decision: 'deny',
      },
      { id: 'broad', match: { tools: ['filesystem.move'], paths: ['C:/**'] }, decision: 'allow' },
    ],
  };
  assert.equal(
    evaluatePolicy(p, { tool: 'filesystem.move', client: 'test', paths: ['C:/ok.txt', 'C:/.env'] })
      .decision,
    'deny',
  );
});
test('web refuses loopback addresses even when domain is configured', async () => {
  const f = await fixture();
  try {
    f.config.toolsets.settings.web.allowed_domains = ['127.0.0.1'];
    await assert.rejects(
      webFetch(f.config, 'https://127.0.0.1/', new AbortController().signal),
      /Non-public/,
    );
    await assert.rejects(
      webFetch(f.config, 'http://127.0.0.1/', new AbortController().signal),
      /denied/,
    );
  } finally {
    await f.cleanup();
  }
});
test('legacy raw shell is not advertised or executable after process-tool migration', async () => {
  const f = await fixture();
  try {
    f.config.toolsets.enabled.push('raw_shell');
    assert.equal(f.executor.list().includes('raw_shell.run'), false);
    assert.equal(f.executor.list().includes('process.run'), false);
    await assert.rejects(
      f.executor.call(
        'raw_shell.run',
        { command: 'echo denied', cwd: f.root },
        f.credential,
        'legacy-shell',
      ),
      /Tool not granted/,
    );
  } finally {
    await f.cleanup();
  }
});
test('real HTTP authentication, local isolation, OAuth consent/PKCE and panic', async () => {
  const f = await fixture();
  const stored = passwordHash('a local test passphrase');
  const vault = {
    async get() {
      return stored;
    },
    async set() {
      throw Error('unused');
    },
  };
  let server;
  try {
    server = await startServer(f.config, f.store, vault, f.audit);
    const base = `http://127.0.0.1:${f.config.server.port}`;
    const owner = `http://127.0.0.1:${f.config.server.owner_port}`;
    assert.equal((await fetch(base + '/mcp', { method: 'POST' })).status, 401);
    assert.equal((await fetch(base + '/local')).status, 403);
    assert.equal(
      (
        await fetch(owner + '/action', {
          method: 'POST',
          headers: { 'content-type': 'application/json', origin: 'https://evil.test' },
          body: '{}',
        })
      ).status,
      403,
    );
    const session = (
      await (
        await fetch(owner + '/login', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ passphrase: 'a local test passphrase' }),
        })
      ).json()
    ).session;
    assert.ok(session);
    const action = async (body) =>
      fetch(owner + '/action', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-owner-session': session },
        body: JSON.stringify(body),
      });
    const initialDashboard = await (await action({ action: 'dashboard' })).json();
    assert.equal(initialDashboard.ownerSessionTimeoutMs, 900000);
    const timeoutResponse = await action({
      action: 'settings.session-timeout',
      timeoutMs: 3600000,
    });
    assert.equal(timeoutResponse.status, 200);
    assert.equal(f.store.snapshot().ownerSessionTimeoutMs, 3600000);
    const reloadedState = await StateStore.load(path.join(f.dir, 'state.json'));
    assert.equal(reloadedState.snapshot().ownerSessionTimeoutMs, 3600000);
    const updatedDashboard = await (await action({ action: 'dashboard' })).json();
    assert.equal(updatedDashboard.ownerSessionTimeoutMs, 3600000);
    const reg = await (
      await fetch(base + '/oauth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_name: 'fixture',
          application_type: 'native',
          redirect_uris: ['http://127.0.0.1:9876/callback'],
          scope: 'mcp',
        }),
      })
    ).json();
    assert.ok(reg.client_id);
    assert.equal(reg.application_type, 'native');
    assert.equal(reg.scope, 'mcp');
    const verifier = 'a'.repeat(64);
    const challenge = Buffer.from(hash(verifier), 'hex').toString('base64url');
    const query = new URLSearchParams({
      client_id: reg.client_id,
      redirect_uri: 'http://127.0.0.1:9876/callback',
      response_type: 'code',
      code_challenge_method: 'S256',
      code_challenge: challenge,
      resource: base + '/mcp',
      state: 'state',
    });
    assert.equal((await fetch(base + '/oauth/authorize?' + query)).status, 200);
    const a = f.store.snapshot().authorizations.at(-1);
    assert.ok(a);
    await action({ action: 'approvals.approve', id: a.approval });
    const poll = await fetch(base + '/oauth/poll?id=' + a.id, { redirect: 'manual' });
    assert.equal(poll.status, 302);
    const code = new URL(poll.headers.get('location')).searchParams.get('code');
    const bad = await fetch(base + '/oauth/token', {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: reg.client_id,
        redirect_uri: a.redirect,
        code,
        code_verifier: 'b'.repeat(64),
        resource: base + '/mcp',
      }),
    });
    assert.equal(bad.status, 400);
    const exchange = await fetch(base + '/oauth/token', {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: reg.client_id,
        redirect_uri: a.redirect,
        code,
        code_verifier: verifier,
        resource: base + '/mcp',
      }),
    });
    const issued = await exchange.json();
    assert.ok(issued.access_token, JSON.stringify(issued));
    const { Client, StreamableHTTPClientTransport } = await import('@modelcontextprotocol/client');
    const client = new Client({ name: 'fixture', version: '1' });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(base + '/mcp'), {
        requestInit: { headers: { authorization: 'Bearer ' + issued.access_token } },
      }),
    );
    const tools = await client.listTools();
    assert.ok(tools.tools.some((t) => t.name === 'ritten.health'));
    const health = await client.callTool({ name: 'ritten.health', arguments: {} });
    assert.notEqual(health.isError, true, JSON.stringify(health));
    const reusedCode = await fetch(base + '/oauth/token', {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: reg.client_id,
        redirect_uri: a.redirect,
        code,
        code_verifier: verifier,
        resource: base + '/mcp',
      }),
    });
    assert.equal(reusedCode.status, 400);
    const refreshBody = {
      grant_type: 'refresh_token',
      client_id: reg.client_id,
      refresh_token: issued.refresh_token,
      resource: base + '/mcp',
    };
    const rotated = await (
      await fetch(base + '/oauth/token', { method: 'POST', body: new URLSearchParams(refreshBody) })
    ).json();
    assert.ok(rotated.access_token);
    const reusedRefresh = await fetch(base + '/oauth/token', {
      method: 'POST',
      body: new URLSearchParams(refreshBody),
    });
    assert.equal(reusedRefresh.status, 400);
    await assert.rejects(authenticate(f.store, rotated.access_token), /Unauthorized/);
    await action({ action: 'panic' });
    assert.equal(
      (
        await fetch(base + '/mcp', {
          method: 'POST',
          headers: { authorization: 'Bearer ' + issued.access_token },
        })
      ).status,
      401,
    );
    await client.close();
    await server.close();
    const persisted = await StateStore.load(f.store.filename);
    assert.equal(persisted.snapshot().panic, true);
    assert.equal(
      persisted.snapshot().clients.every((c) => c.revoked),
      true,
    );
  } finally {
    if (server) await server.close();
    await f.cleanup();
  }
});
test('required audit failure blocks execution and preserves uncertain mutation state', async () => {
  const f = await fixture();
  try {
    f.config.policy.rules.unshift({
      id: 'write-direct',
      match: { tools: ['filesystem.write_file'] },
      decision: 'allow',
    });
    const unavailable = {
      async record() {
        throw Error('Audit unavailable');
      },
    };
    const before = new Executor(f.config, f.store, unavailable);
    await assert.rejects(
      before.call(
        'filesystem.write_file',
        { path: path.join(f.root, 'file.txt'), content: 'not-written' },
        f.credential,
        'failure-before',
      ),
      /Audit unavailable/,
    );
    assert.equal(await readFile(path.join(f.root, 'file.txt'), 'utf8'), 'hello');
    const after = new Executor(f.config, f.store, {
      async record(event) {
        if (event.event === 'tool.completed') throw Error('Completion audit unavailable');
      },
    });
    await assert.rejects(
      after.call(
        'filesystem.write_file',
        { path: path.join(f.root, 'file.txt'), content: 'effect-completed' },
        f.credential,
        'failure-after',
      ),
      /Completion audit unavailable/,
    );
    assert.equal(await readFile(path.join(f.root, 'file.txt'), 'utf8'), 'effect-completed');
    await assert.rejects(
      f.executor.call(
        'filesystem.write_file',
        { path: path.join(f.root, 'file.txt'), content: 'effect-completed' },
        f.credential,
        'failure-after',
      ),
      /indeterminate/,
    );
  } finally {
    await f.cleanup();
  }
});
test('corrupt persisted state fails closed', async () => {
  const f = await fixture();
  try {
    await writeFile(f.store.filename, JSON.stringify({ version: 1, panic: false }));
    await assert.rejects(StateStore.load(f.store.filename));
  } finally {
    await f.cleanup();
  }
});
test('pause/resume, health fingerprints and result caps', async () => {
  const f = await fixture();
  try {
    await f.store.change((s) => {
      s.paused = true;
    });
    await assert.rejects(f.executor.call('ritten.health', {}, f.credential, 'paused'), /paused/);
    await f.store.change((s) => {
      s.paused = false;
    });
    const health = await f.executor.call('ritten.health', {}, f.credential, 'resumed');
    assert.match(health.fingerprints.builtin, /^[a-f0-9]{64}$/);
    f.config.server.result_limit = '1B';
    const capped = await f.executor.call(
      'filesystem.read_file',
      { path: path.join(f.root, 'file.txt') },
      f.credential,
      'capped',
    );
    assert.equal(capped.truncated, true);
  } finally {
    await f.cleanup();
  }
});
test('shell cancellation terminates a running subprocess', async () => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 100);
  try {
    const result = await runShell(
      process.platform === 'win32' ? 'ping -n 20 127.0.0.1' : 'sleep 20',
      tmpdir(),
      controller.signal,
    );
    assert.equal(result.cancelled, true);
    assert.equal(
      result.terminationFailed,
      false,
      'Process-tree termination requires OS permissions',
    );
    assert.ok(
      result.durationMs < 8000,
      'Cancellation must stop execution, not wait for normal exit',
    );
  } finally {
    clearTimeout(timeout);
  }
});
test('directory/move/delete scopes and replay after source disappearance', async () => {
  const f = await fixture();
  try {
    f.config.policy.rules.unshift({
      id: 'mutations',
      match: {
        tools: ['filesystem.create_directory', 'filesystem.move', 'filesystem.delete'],
        paths: [f.root.replaceAll('\\', '/') + '/**'],
      },
      decision: 'allow',
    });
    const directory = path.join(f.root, 'created');
    await f.executor.call(
      'filesystem.create_directory',
      { path: directory },
      f.credential,
      'mkdir',
    );
    const source = path.join(f.root, 'file.txt');
    const destination = path.join(directory, 'moved.txt');
    await f.executor.call('filesystem.move', { path: source, destination }, f.credential, 'move');
    const restarted = new Executor(f.config, await StateStore.load(f.store.filename), f.audit);
    assert.equal(
      (await restarted.call('filesystem.move', { path: source, destination }, f.credential, 'move'))
        .moved,
      true,
    );
    await assert.rejects(
      f.executor.call(
        'filesystem.move',
        { path: destination, destination: path.join(f.dir, 'outside.txt') },
        f.credential,
        'escape-move',
      ),
      /outside/,
    );
    await assert.rejects(
      f.executor.call('filesystem.delete', { path: directory }, f.credential, 'nonempty'),
      /not empty|ENOTEMPTY/i,
    );
    await f.executor.call('filesystem.delete', { path: destination }, f.credential, 'delete');
    assert.equal(
      (await f.executor.call('filesystem.delete', { path: destination }, f.credential, 'delete'))
        .deleted,
      true,
    );
    await assert.rejects(
      f.executor.call('filesystem.delete', { path: f.root }, f.credential, 'root-delete'),
      /outside/,
    );
    await f.executor.call('filesystem.delete', { path: directory }, f.credential, 'empty-dir');
  } finally {
    await f.cleanup();
  }
});

test('stateless HTTP accepts reused RPC IDs and explicit idempotency keys prevent replay', async () => {
  const f = await fixture();
  f.config.policy.rules.find((r) => r.id === 'write').decision = 'allow';
  let server;
  try {
    server = await startServer(
      f.config,
      f.store,
      { get: async () => 'unused', set: async () => {} },
      f.audit,
    );
    const url = `http://127.0.0.1:${f.config.server.port}/mcp`;
    const file = path.join(f.root, 'http-write.txt');
    const call = async (content, key) => {
      const headers = {
        authorization: `Bearer ${f.token}`,
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
        'mcp-protocol-version': '2025-03-26',
      };
      if (key !== undefined) headers['idempotency-key'] = key;
      const res = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'filesystem.write_file', arguments: { path: file, content } },
        }),
      });
      const text = await res.text();
      const payload = res.headers.get('content-type')?.includes('text/event-stream')
        ? text
            .split('\n')
            .find((line) => line.startsWith('data: '))
            ?.slice(6)
        : text;
      return { status: res.status, body: JSON.parse(payload) };
    };
    assert.notEqual((await call('first')).body.result?.isError, true);
    assert.notEqual((await call('second')).body.result?.isError, true);
    assert.equal(await readFile(file, 'utf8'), 'second');
    assert.notEqual((await call('keyed', 'operation-1')).body.result?.isError, true);
    await writeFile(file, 'external');
    assert.notEqual((await call('keyed', 'operation-1')).body.result?.isError, true);
    assert.equal(await readFile(file, 'utf8'), 'external');
    assert.equal((await call('changed', 'operation-1')).body.result?.isError, true);
    assert.equal((await call('bad', 'invalid key')).status, 400);
  } finally {
    if (server) await server.close();
    await f.cleanup();
  }
});

test('coding tools read, search, protect denied descendants and apply exact edits', async () => {
  const f = await fixture();
  try {
    f.config.toolsets.enabled.push('coding');
    f.credential.paths.push(f.root.replaceAll('\\', '/'));
    const root = f.root.replaceAll('\\', '/');
    f.config.policy.rules.unshift(
      { id: 'coding-secret', match: { tools: ['coding.*'], paths: ['**/.env'] }, decision: 'deny' },
      {
        id: 'coding-all',
        match: { tools: ['coding.*'], paths: [root, root + '/**'] },
        decision: 'allow',
      },
    );
    await writeFile(path.join(f.root, '.env'), 'secret-test');
    const read = await f.executor.call(
      'coding.read',
      { path: path.join(f.root, 'file.txt') },
      f.credential,
      'coding-read',
    );
    assert.equal(read.lines[0].text, 'hello');
    const grep = await f.executor.call(
      'coding.grep',
      { path: f.root, query: 'secret-test' },
      f.credential,
      'coding-grep',
    );
    assert.equal(grep.results.length, 0);
    const glob = await f.executor.call(
      'coding.glob',
      { path: f.root, pattern: '**/*' },
      f.credential,
      'coding-glob',
    );
    assert.equal(
      glob.results.some((x) => x.path.endsWith('.env')),
      false,
    );
    await f.executor.call(
      'coding.edit',
      { path: path.join(f.root, 'file.txt'), old_text: 'hello', new_text: 'world' },
      f.credential,
      'coding-edit',
    );
    assert.equal(await readFile(path.join(f.root, 'file.txt'), 'utf8'), 'world');
    await assert.rejects(
      f.executor.call(
        'coding.edit',
        { path: path.join(f.root, 'file.txt'), old_text: 'hello', new_text: 'bad' },
        f.credential,
        'coding-stale',
      ),
      /match/,
    );
    await f.executor.call(
      'coding.write',
      { path: path.join(f.root, 'new.txt'), content: 'new' },
      f.credential,
      'coding-write',
    );
    assert.equal(await readFile(path.join(f.root, 'new.txt'), 'utf8'), 'new');
    await assert.rejects(
      f.executor.call(
        'coding.write',
        { path: path.join(f.root, 'new.txt'), content: 'overwrite' },
        f.credential,
        'coding-overwrite',
      ),
      /exists/,
    );
  } finally {
    await f.cleanup();
  }
});

test('process.run is advertised only when enabled and requires executable plus folder policy', async () => {
  const f = await fixture();
  try {
    assert.equal(f.executor.list().includes('process.list_allowed'), false);
    f.config.toolsets.enabled.push('process');
    f.credential.paths.push(f.root.replaceAll('\\', '/'));
    assert.equal(f.executor.list().includes('process.run'), true);
    assert.equal(f.executor.list().includes('process.list_allowed'), true);
    const executable = process.execPath.replaceAll('\\', '/');
    const cwd = f.root.replaceAll('\\', '/');
    const args = { executable, args: ['-e', 'process.stdout.write("process-ready")'], cwd: f.root };
    await assert.rejects(
      f.executor.call('process.run', args, f.credential, 'process-denied'),
      /Policy denied/,
    );
    f.config.policy.rules.unshift({
      id: 'process-node',
      match: { tools: ['process.run'], paths: [cwd, `${cwd}/**`], executables: [executable] },
      decision: 'allow',
    });
    const result = await f.executor.call('process.run', args, f.credential, 'process-allowed');
    assert.equal(result.status, 'exited');
    assert.equal(result.exit_code, 0);
    assert.equal(result.stdout, 'process-ready');
    const large = await f.executor.call(
      'process.run',
      {
        executable,
        args: ['-e', 'process.stdout.write("x".repeat(4096))'],
        cwd: f.root,
        max_output_bytes: 1024,
      },
      f.credential,
      'process-large-output',
    );
    assert.equal(Buffer.byteLength(large.stdout) + Buffer.byteLength(large.stderr), 1024);
    assert.equal(large.output_truncated, true);
    const audit = await f.audit.tail();
    assert.doesNotMatch(audit, /process-ready/);
  } finally {
    await f.cleanup();
  }
});

test('process.run returns a bounded timeout result', async () => {
  const f = await fixture();
  try {
    f.config.toolsets.enabled.push('process');
    f.credential.paths.push(f.root.replaceAll('\\', '/'));
    const executable = process.execPath.replaceAll('\\', '/');
    const cwd = f.root.replaceAll('\\', '/');
    f.config.policy.rules.unshift({
      id: 'process-timeout',
      match: { tools: ['process.run'], paths: [cwd, `${cwd}/**`], executables: [executable] },
      decision: 'allow',
    });
    const result = await f.executor.call(
      'process.run',
      {
        executable,
        args: ['-e', 'setTimeout(() => {}, 5000)'],
        cwd: f.root,
        timeout_ms: 100,
      },
      f.credential,
      'process-timeout',
    );
    assert.equal(result.status, 'timed_out');
    assert.notEqual(result.exit_code, 0);
  } finally {
    await f.cleanup();
  }
});

test('process.run_task executes only the configured task after task and executable authorization', async () => {
  const f = await fixture();
  try {
    f.config.toolsets.enabled.push('process');
    f.credential.paths.push(f.root.replaceAll('\\', '/'));
    const executable = process.execPath.replaceAll('\\', '/');
    const cwd = f.root.replaceAll('\\', '/');
    f.config.toolsets.settings.process.tasks['node-version'] = {
      executable,
      args: ['--version'],
      cwd: f.root,
    };
    f.config.policy.rules.unshift({
      id: 'process-node-task',
      match: {
        tools: ['process.run_task'],
        tasks: ['node-version'],
        paths: [cwd, `${cwd}/**`],
        executables: [executable],
      },
      decision: 'allow',
    });
    const result = await f.executor.call(
      'process.run_task',
      { task: 'node-version' },
      f.credential,
      'process-task',
    );
    assert.equal(result.status, 'exited');
    assert.match(result.stdout, /^v\d/);
    await assert.rejects(
      f.executor.call(
        'process.run_task',
        { task: 'node-version', executable },
        f.credential,
        'process-task-override',
      ),
      /Unrecognized key/,
    );
  } finally {
    await f.cleanup();
  }
});

test('process.list_allowed reports only effective client executable and task permissions', async () => {
  const f = await fixture();
  try {
    f.config.toolsets.enabled.push('process');
    const root = f.root.replaceAll('\\', '/');
    f.credential.paths.push(root);
    const executable = process.execPath.replaceAll('\\', '/');
    f.config.toolsets.settings.process.tasks['node-version'] = {
      executable,
      args: ['--version'],
      cwd: f.root,
    };
    f.config.toolsets.settings.process.tasks['out-of-scope'] = {
      executable,
      args: ['--version'],
      cwd: path.dirname(f.root),
    };
    f.config.policy.rules.unshift(
      {
        id: 'list-allowed-self',
        match: { tools: ['process.list_allowed'] },
        decision: 'allow',
      },
      {
        id: 'list-process-run',
        match: {
          tools: ['process.run'],
          paths: [root, `${root}/**`],
          executables: [executable],
        },
        decision: 'ask',
      },
      {
        id: 'list-process-task',
        match: {
          tools: ['process.run_task'],
          tasks: ['node-version'],
          paths: [root, `${root}/**`],
          executables: [executable],
        },
        decision: 'allow',
      },
      {
        id: 'other-client-only',
        match: {
          tools: ['process.run'],
          clients: ['someone-else'],
          paths: [root, `${root}/**`],
          executables: [executable],
        },
        decision: 'allow',
      },
    );
    const result = await f.executor.call('process.list_allowed', {}, f.credential, 'list-allowed');
    assert.deepEqual(Object.keys(result).sort(), ['executables', 'tasks']);
    assert.deepEqual(result.executables, [
      {
        path: executable,
        decision: 'ask',
        working_directories: [root, `${root}/**`],
      },
    ]);
    assert.deepEqual(result.tasks, [
      {
        name: 'node-version',
        executable,
        args: ['--version'],
        cwd: root,
        decision: 'allow',
      },
    ]);
  } finally {
    await f.cleanup();
  }
});
