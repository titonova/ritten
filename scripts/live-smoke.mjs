// Explicitly invoked only. Creates isolated fixture files, temporary credentials,
// and two loopback listeners; never reads the owner's configured roots or vault.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { configSchema } from '../dist/config/schema.js';
import { StateStore } from '../dist/storage/state.js';
import { AuditLog } from '../dist/audit/log.js';
import { passwordHash, hash, secret } from '../dist/auth/credentials.js';
import { startServer } from '../dist/server/http.js';

const origin = process.argv[2];
if (!origin || new URL(origin).protocol !== 'https:')
  throw Error('Usage: node scripts/live-smoke.mjs https://PUBLIC_ORIGIN');
const directory = await mkdtemp(path.join(tmpdir(), 'ritten-live-'));
let server;
let client;
try {
  const root = path.join(directory, 'fixtures');
  await mkdir(root);
  const source = path.join(root, 'read.txt');
  const destination = path.join(root, 'write.txt');
  await writeFile(source, 'isolated fixture');
  const config = configSchema.parse({
    version: 1,
    server: {
      host: '127.0.0.1',
      port: 19337,
      owner_port: 19338,
      public_url: origin,
      request_timeout: '30s',
    },
    toolsets: {
      enabled: ['ritten', 'filesystem'],
      settings: { filesystem: { roots: [{ path: root, access: 'read-write' }] } },
    },
    policy: {
      default: 'deny',
      approval_timeout: '20s',
      rules: [
        { id: 'health', match: { tools: ['ritten.health'] }, decision: 'allow' },
        {
          id: 'read',
          match: { tools: ['filesystem.read_file'], paths: [root.replaceAll('\\', '/') + '/**'] },
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
  const passphrase = secret();
  const verifierHash = passwordHash(passphrase);
  const vault = {
    async get() {
      return verifierHash;
    },
    async set() {
      throw Error('No persistent vault in fixture');
    },
  };
  const store = await StateStore.load(path.join(directory, 'state.json'));
  const audit = new AuditLog(path.join(directory, 'logs'), config.logging);
  server = await startServer(config, store, vault, audit);
  const publicFetch = (route, options = {}) =>
    fetch(origin + route, {
      ...options,
      headers: { 'ngrok-skip-browser-warning': 'ritten-smoke', ...options.headers },
      signal: AbortSignal.timeout(30000),
    });
  const metadata = await (await publicFetch('/.well-known/oauth-protected-resource')).json();
  assert.equal(metadata.resource, origin + '/mcp');
  assert.equal((await publicFetch('/local')).status, 403);
  assert.equal((await publicFetch('/mcp', { method: 'POST' })).status, 401);
  const registration = await (
    await publicFetch('/oauth/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: 'Ritten isolated smoke',
        redirect_uris: ['http://127.0.0.1:19339/callback'],
      }),
    })
  ).json();
  assert.ok(registration.client_id);
  const verifier = secret() + secret();
  const challenge = Buffer.from(hash(verifier), 'hex').toString('base64url');
  const params = new URLSearchParams({
    client_id: registration.client_id,
    redirect_uri: 'http://127.0.0.1:19339/callback',
    response_type: 'code',
    code_challenge_method: 'S256',
    code_challenge: challenge,
    resource: origin + '/mcp',
    state: 'fixture',
  });
  assert.equal((await publicFetch('/oauth/authorize?' + params)).status, 200);
  const session = (
    await (
      await fetch('http://127.0.0.1:19338/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ passphrase }),
      })
    ).json()
  ).session;
  const action = async (body) => {
    const res = await fetch('http://127.0.0.1:19338/action', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-owner-session': session },
      body: JSON.stringify(body),
    });
    assert.equal(res.status, 200);
    return res.json();
  };
  const auth = store.snapshot().authorizations.at(-1);
  await action({ action: 'approvals.approve', id: auth.approval });
  const poll = await publicFetch('/oauth/poll?id=' + auth.id, { redirect: 'manual' });
  assert.equal(poll.status, 302);
  const code = new URL(poll.headers.get('location')).searchParams.get('code');
  const tokens = await (
    await publicFetch('/oauth/token', {
      method: 'POST',
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: registration.client_id,
        redirect_uri: auth.redirect,
        code,
        code_verifier: verifier,
        resource: origin + '/mcp',
      }),
    })
  ).json();
  assert.ok(tokens.access_token);
  client = new Client({ name: 'Ritten-live-smoke', version: '1' });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(origin + '/mcp'), {
      requestInit: {
        headers: {
          authorization: 'Bearer ' + tokens.access_token,
          'ngrok-skip-browser-warning': 'ritten-smoke',
        },
      },
    }),
  );
  const health = await client.callTool({ name: 'ritten.health', arguments: {} });
  assert.notEqual(health.isError, true, JSON.stringify(health));
  const read = await client.callTool({ name: 'filesystem.read_file', arguments: { path: source } });
  assert.notEqual(read.isError, true, JSON.stringify(read));
  assert.match(JSON.stringify(read), /isolated fixture/);
  const write = client.callTool({
    name: 'filesystem.write_file',
    arguments: { path: destination, content: 'approved fixture write' },
  });
  let approval;
  for (let i = 0; i < 200; i++) {
    approval = store.snapshot().approvals.find((a) => a.kind === 'tool' && a.status === 'pending');
    if (approval) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  assert.ok(approval);
  assert.equal(approval.arguments.content, 'approved fixture write');
  await action({ action: 'approvals.approve', id: approval.id });
  const written = await write;
  assert.notEqual(written.isError, true, JSON.stringify(written));
  assert.equal(await readFile(destination, 'utf8'), 'approved fixture write');
  const denied = await client.callTool({
    name: 'filesystem.read_file',
    arguments: { path: path.join(directory, 'state.json') },
  });
  assert.equal(denied.isError, true);
  await action({ action: 'panic' });
  assert.equal(
    (
      await publicFetch('/mcp', {
        method: 'POST',
        headers: { authorization: 'Bearer ' + tokens.access_token },
      })
    ).status,
    401,
  );
  const events = await audit.tail();
  assert.match(events, /tool.completed/);
  assert.doesNotMatch(events, new RegExp(tokens.access_token));
  console.log(
    JSON.stringify(
      {
        passed: true,
        transport: 'ngrok HTTPS',
        checks: [
          'metadata',
          'public owner-route denial',
          'unauthenticated denial',
          'OAuth registration/local consent/PKCE',
          'official SDK health/read',
          'locally approved write',
          'out-of-scope denial',
          'panic revocation',
          'redacted audit',
        ],
        isolatedFixtures: true,
      },
      null,
      2,
    ),
  );
} finally {
  if (client) await client.close();
  if (server) await server.close();
  await rm(directory, { recursive: true, force: true });
}
