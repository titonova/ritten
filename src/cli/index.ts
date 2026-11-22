#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { access, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { stringify } from 'yaml';
import { getPaths } from '../app/paths.js';
import { loadConfig } from '../config/loader.js';
import { defaultConfig } from '../config/schema.js';
import { StateStore, atomicWrite, acquireLock } from '../storage/state.js';
import { systemVault, passwordHash } from '../auth/credentials.js';
import { AuditLog } from '../audit/log.js';
import { startServer } from '../server/http.js';
import { toolDefinitions } from '../executor/pipeline.js';
import { evaluatePolicy } from '../policy/engine.js';
import { discover, reserved } from '../toolsets/loader.js';

const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as {
  version: string;
};
const args = process.argv.slice(2);
const paths = getPaths();
function print(value: unknown): void {
  console.log(typeof value === 'string' ? value : JSON.stringify(value, null, 2));
}
async function hidden(prompt: string): Promise<string> {
  if (!process.stdin.isTTY || !process.stdin.setRawMode)
    throw new Error(
      'Owner authentication requires an interactive local terminal; use the local console for browser access',
    );
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let value = '';
    const done = () => {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.removeListener('data', onData);
      process.stdout.write('\n');
    };
    const onData = (chunk: Buffer) => {
      for (const char of chunk.toString('utf8')) {
        if (char === '\u0003') {
          done();
          reject(new Error('Cancelled'));
          return;
        }
        if (char === '\r' || char === '\n') {
          done();
          resolve(value);
          return;
        }
        if (char === '\u007f' || char === '\b') value = value.slice(0, -1);
        else if (char >= ' ' && value.length < 1024) value += char;
      }
    };
    process.stdin.on('data', onData);
  });
}
async function admin(action: string, extra: Record<string, unknown> = {}) {
  const config = await loadConfig(paths.config);
  const base = `http://127.0.0.1:${config.server.owner_port}`;
  const passphrase = await hidden('Owner passphrase: ');
  const login = await fetch(`${base}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ passphrase }),
    signal: AbortSignal.timeout(10000),
  });
  const session = (await login.json()) as { session?: string; error?: string };
  if (!login.ok || !session.session) throw new Error(session.error ?? 'Login failed');
  const response = await fetch(`${base}/action`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-owner-session': session.session },
    body: JSON.stringify({ action, ...extra }),
    signal: AbortSignal.timeout(10000),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(JSON.stringify(result));
  return result;
}
async function main(): Promise<void> {
  const command = args.join(' ');
  if (!args.length || args.includes('--help') || args.includes('-h')) {
    print(
      `Ritten — permissioned MCP gateway (under development)\n\nCommands:\n  setup\n  start --foreground\n  paths\n  config path|validate|show --effective\n  tools list\n  status\n  approvals list|approve <id>|deny <id>\n  tokens list|create <JSON options>|revoke <id>|revoke-all\n  clients list|revoke <id>|revoke-all\n  pause | resume | panic\n  setup access --restore\n  logs tail\n  doctor\n\nOwner commands prompt locally for the passphrase. See docs/QUICKSTART.md.`,
    );
    return;
  }
  if (command === '--version' || command === '-v') {
    print(pkg.version);
    return;
  }
  if (command === 'paths') {
    print(paths);
    return;
  }
  if (command === 'config path') {
    print(paths.config);
    return;
  }
  if (command === 'setup') {
    await access(paths.config).then(
      () => {
        throw new Error('Configuration already exists; refusing to overwrite');
      },
      (e) => {
        if (e.code !== 'ENOENT') throw e;
      },
    );
    const release = await acquireLock(paths.data);
    try {
      const vault = await systemVault(paths.data);
      const first = await hidden('Create owner passphrase (at least 12 characters): ');
      const second = await hidden('Repeat passphrase: ');
      if (first.length < 12 || first !== second)
        throw new Error('Passphrases must match and contain at least 12 characters');
      await vault.set(passwordHash(first));
      await atomicWrite(paths.config, stringify(defaultConfig));
      await mkdir(paths.toolsets, { recursive: true, mode: 0o700 });
      const store = await StateStore.load(path.join(paths.data, 'state.json'));
      await store.change(() => {});
      print(
        `Setup complete. Edit ${paths.config} to add explicit roots and policy. No access is allowed by default.`,
      );
    } finally {
      await release();
    }
    return;
  }
  if (command === 'config validate') {
    await loadConfig(paths.config);
    print('Configuration is valid.');
    return;
  }
  if (command === 'config show --effective') {
    print(await loadConfig(paths.config));
    return;
  }
  if (command === 'tools list') {
    print(await admin('tools.list'));
    return;
  }
  if (command === 'toolsets list') {
    const config = await loadConfig(paths.config);
    const found = await discover([
      ...(process.env.RITTEN_TOOLSET_PATHS?.split(path.delimiter).filter(Boolean) ?? []),
      ...config.toolsets.directories,
      paths.toolsets,
    ]);
    print(
      [...reserved, ...found.keys()].map((name) => ({
        name,
        enabled: config.toolsets.enabled.includes(name),
        builtin: reserved.has(name),
      })),
    );
    return;
  }
  if (command === 'start' || command === 'start --foreground') {
    const config = await loadConfig(paths.config);
    const release = await acquireLock(paths.data);
    try {
      const vault = await systemVault(paths.data);
      if (!(await vault.get())) throw new Error('Owner credential missing; run setup');
      const store = await StateStore.load(path.join(paths.data, 'state.json'));
      const audit = new AuditLog(paths.logs, config.logging);
      const server = await startServer(config, store, vault, audit);
      print(
        `MCP: http://127.0.0.1:${config.server.port}/mcp\nOwner console: http://127.0.0.1:${config.server.owner_port}/local\nForeground mode. Keep this process running.`,
      );
      await Promise.race([
        server.stopped,
        new Promise<void>((resolve) => {
          const stop = () => resolve();
          process.once('SIGINT', stop);
          process.once('SIGTERM', stop);
        }),
      ]);
      await server.close();
    } finally {
      await release();
    }
    return;
  }
  if (command === 'doctor') {
    const config = await loadConfig(paths.config);
    const vault = await systemVault(paths.data);
    print({
      node: process.version,
      config: 'valid',
      ownerCredential: Boolean(await vault.get()),
      publicUrl: config.server.public_url,
      transport: 'manual',
      state: 'No connectivity or hosted-client verification performed',
    });
    return;
  }
  if (command === 'status' || ['pause', 'resume', 'panic'].includes(command)) {
    print(await admin(command));
    return;
  }
  if (command === 'stop') {
    print(await admin('stop'));
    return;
  }
  if (args[0] === 'policy' && args[1] === 'check') {
    if (!args[2] || !args[3])
      throw new Error('Usage: policy check <tool> <JSON with client, paths, domains, commands>');
    const config = await loadConfig(paths.config);
    print({
      ...evaluatePolicy(config.policy, { ...JSON.parse(args[3]), tool: args[2] }),
      note: 'Policy simulation only; live execution also validates credentials, canonical resources, and tool limits',
    });
    return;
  }
  if (command === 'policy validate') {
    await loadConfig(paths.config);
    print('Policy configuration is valid.');
    return;
  }
  if (command === 'setup access --restore') {
    print(await admin('restore'));
    return;
  }
  if (command === 'toolsets enable raw_shell' || command === 'toolsets disable raw_shell') {
    throw new Error(
      'raw_shell is deprecated and unavailable. Configure the disabled-by-default process toolset with explicit executable and folder policies.',
    );
  }
  if (command === 'logs tail') {
    print(await admin('logs.tail'));
    return;
  }
  if (['approvals', 'tokens', 'clients'].includes(args[0] ?? '')) {
    const group = args[0]!;
    const sub = args[1];
    const allowed =
      group === 'approvals'
        ? ['list', 'approve', 'deny']
        : group === 'tokens'
          ? ['list', 'create', 'revoke', 'revoke-all']
          : ['list', 'revoke', 'revoke-all'];
    if (!sub || !allowed.includes(sub)) throw new Error('Unsupported subcommand');
    if (sub === 'create') {
      if (!args[2]) throw new Error('Provide JSON options: name, client, tools, paths, domains');
      print(await admin('tokens.create', { options: JSON.parse(args[2]) }));
    } else {
      if (['approve', 'deny', 'revoke'].includes(sub) && !args[2])
        throw new Error('Identifier required');
      print(await admin(`${group}.${sub}`, { id: args[2] ?? '' }));
    }
    return;
  }
  process.exitCode = 2;
  throw new Error('Unknown command or option. Run ritten --help');
}
try {
  await main();
} catch (e) {
  console.error(e instanceof Error ? e.message : 'Operation failed');
  process.exitCode ||= 1;
}
