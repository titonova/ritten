import { z } from 'zod';
import { passwordMatches, secret, issueCredential, type OwnerVault } from '../auth/credentials.js';
import { json } from '../auth/oauth.js';
import { StateStore } from '../storage/state.js';
import { Executor } from '../executor/pipeline.js';
import { AuditLog } from '../audit/log.js';
import { getPaths } from '../app/paths.js';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { credentialIsLive } from '../auth/credentials.js';
import { ownerPage as page } from './page.js';

const tokenInput = z.strictObject({
  name: z.string().min(1).max(100),
  client: z.string().min(1).max(100),
  tools: z.array(z.string().min(1)).min(1),
  paths: z.array(z.string()).default([]),
  domains: z.array(z.string()).default([]),
});
const ownerSessionTimeoutInput = z.union([
  z.literal(900000),
  z.literal(3600000),
  z.literal(86400000),
]);
export class OwnerService {
  onStop: (() => void) | undefined;
  private sessions = new Map<string, number>();
  private failures = 0;
  private lockedUntil = 0;
  constructor(
    readonly store: StateStore,
    readonly vault: OwnerVault,
    readonly executor: Executor,
    readonly audit: AuditLog,
  ) {}
  async handle(request: Request): Promise<Response> {
    const u = new URL(request.url);
    if (u.pathname === '/local' && request.method === 'GET')
      return new Response(page, {
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'content-security-policy':
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'",
          'cache-control': 'no-store',
          'x-content-type-options': 'nosniff',
        },
      });
    if (request.method !== 'POST' || request.headers.get('content-type') !== 'application/json')
      return json({ error: 'POST JSON required' }, 405);
    if (u.pathname === '/login') {
      if (Date.now() < this.lockedUntil) return json({ error: 'Login temporarily locked' }, 429);
      const data = z.strictObject({ passphrase: z.string().max(1024) }).parse(await request.json());
      const stored = await this.vault.get();
      if (!stored || !passwordMatches(data.passphrase, stored)) {
        this.failures++;
        if (this.failures >= 5) {
          this.lockedUntil = Date.now() + 900000;
          this.failures = 0;
        }
        await this.audit.record({ event: 'owner.login_failed' });
        return json({ error: 'Unauthorized' }, 401);
      }
      this.failures = 0;
      for (const [s, expires] of this.sessions) if (expires < Date.now()) this.sessions.delete(s);
      const session = secret();
      this.sessions.set(session, Date.now() + this.store.snapshot().ownerSessionTimeoutMs);
      await this.audit.record({ event: 'owner.login' });
      return json({ session });
    }
    if ((this.sessions.get(request.headers.get('x-owner-session') ?? '') ?? 0) <= Date.now())
      return json({ error: 'Unauthorized' }, 401);
    const body = z.record(z.string(), z.unknown()).parse(await request.json());
    const action = z.string().parse(body.action);
    const id = typeof body.id === 'string' ? body.id : '';
    if (action === 'dashboard') {
      const s = this.store.snapshot();
      const config = this.executor.config;
      const now = Date.now();
      const clients = s.clients.map((client) => {
        const credentials = s.credentials.filter(
          (c) => c.client === client.id && c.kind === 'access',
        );
        return {
          ...client,
          active: !client.revoked && credentials.some((c) => credentialIsLive(c, now)),
          lastUsed: Math.max(0, ...credentials.map((c) => c.lastUsed ?? 0)) || null,
        };
      });
      return json({
        status: { paused: s.paused, panic: s.panic, tools: this.executor.list(), pid: process.pid },
        clients,
        approvals: s.approvals
          .filter((a) => a.status === 'pending' && a.expires > now)
          .map(({ binding: _binding, ...a }) => a),
        paths: getPaths(),
        roots: config.toolsets.settings.filesystem.roots,
        publicUrl: config.server.public_url,
        policy: config.policy.default,
        policyRules: config.policy.rules,
        enabledToolsets: config.toolsets.enabled,
        ownerSessionTimeoutMs: s.ownerSessionTimeoutMs,
        audit: await this.audit.tail(),
      });
    }
    await this.audit.record({ event: 'owner.action', action, id });
    if (action === 'settings.session-timeout') {
      const parsedTimeout = ownerSessionTimeoutInput.safeParse(body.timeoutMs);
      if (!parsedTimeout.success)
        return json({ error: 'Choose 15 minutes, 1 hour, or 24 hours' }, 400);
      const timeoutMs = parsedTimeout.data;
      await this.store.change((state) => {
        state.ownerSessionTimeoutMs = timeoutMs;
      });
      const nextExpiry = Date.now() + timeoutMs;
      for (const [session, expires] of this.sessions) {
        if (expires <= Date.now()) this.sessions.delete(session);
        else this.sessions.set(session, nextExpiry);
      }
      await this.audit.record({ event: 'owner.session_timeout_updated', timeoutMs });
      return json({ ownerSessionTimeoutMs: timeoutMs });
    }
    if (action === 'paths.open') {
      if (process.platform !== 'win32')
        return json({ error: 'Opening paths is currently supported on Windows only' }, 400);
      const paths = getPaths();
      const known: Record<string, string> = {
        config: paths.config,
        data: paths.data,
        logs: paths.logs,
        toolsets: paths.toolsets,
      };
      const target = id.startsWith('root:')
        ? this.executor.config.toolsets.settings.filesystem.roots[Number(id.slice(5))]?.path
        : known[id];
      if (!target) return json({ error: 'Unknown path' }, 400);
      const resolved = path.resolve(target);
      const child = spawn('explorer.exe', [resolved], { detached: true, stdio: 'ignore' });
      const started = await new Promise<boolean>((resolve) => {
        child.once('spawn', () => resolve(true));
        child.once('error', () => resolve(false));
      });
      if (!started) return json({ error: 'Could not start File Explorer' }, 500);
      child.unref();
      return json({ launched: true });
    }
    if (action === 'status') {
      const s = this.store.snapshot();
      return json({
        running: true,
        paused: s.paused,
        panic: s.panic,
        tools: this.executor.list(),
        pid: process.pid,
      });
    }
    if (action === 'tools.list')
      return json(
        this.executor.list().map((name) => {
          const d = this.executor.definition(name);
          return { name, description: d.description, readOnly: d.readOnly };
        }),
      );
    if (action === 'stop') {
      setTimeout(() => this.onStop?.(), 200);
      return json({ stopping: true });
    }
    if (action === 'toolsets.enable.raw_shell' || action === 'toolsets.disable.raw_shell') {
      return json(
        {
          error:
            'raw_shell is deprecated and unavailable; configure process.* with explicit executable and folder policy.',
        },
        410,
      );
    }
    if (action === 'approvals.list')
      return json(
        this.store.snapshot().approvals.map((a) => ({
          ...a,
          binding: undefined,
          status: a.expires <= Date.now() && a.status === 'pending' ? 'expired' : a.status,
        })),
      );
    if (action === 'approvals.approve' || action === 'approvals.deny') {
      await this.store.change((s) => {
        if (s.panic) throw new Error('Panic lock active');
        const a = s.approvals.find((a) => a.id === id);
        if (!a || a.status !== 'pending' || a.expires <= Date.now())
          throw new Error('Approval unavailable');
        a.status = action.endsWith('approve') ? 'approved' : 'denied';
      });
      return json({ updated: true });
    }
    if (action === 'tokens.create') {
      if (this.store.snapshot().panic) return json({ error: 'Panic lock active' }, 403);
      const options = tokenInput.parse(body.options);
      const result = await issueCredential(this.store, { ...options, kind: 'bearer' });
      return json({ id: result.credential.id, token: result.token });
    }
    if (action === 'tokens.list')
      return json(
        this.store
          .snapshot()
          .credentials.filter((c) => c.kind === 'bearer')
          .map(({ hash: _hash, ...c }) => c),
      );
    if (action === 'clients.list') return json(this.store.snapshot().clients);
    if (
      action === 'tokens.revoke' ||
      action === 'tokens.revoke-all' ||
      action === 'clients.revoke' ||
      action === 'clients.revoke-all'
    ) {
      await this.store.change((s) => {
        if (action.startsWith('tokens')) {
          for (const c of s.credentials)
            if (action.endsWith('all') || c.id === id) c.revoked = true;
        } else {
          for (const c of s.clients) if (action.endsWith('all') || c.id === id) c.revoked = true;
        }
      });
      this.executor.cancelAll();
      return json({ revoked: true });
    }
    if (['pause', 'resume', 'panic', 'restore'].includes(action)) {
      await this.store.change((s) => {
        if (action === 'pause') s.paused = true;
        if (action === 'resume') {
          if (s.panic) throw new Error('Panic lock requires restore');
          s.paused = false;
        }
        if (action === 'panic') {
          s.panic = true;
          s.paused = true;
          for (const c of s.credentials) c.revoked = true;
          for (const c of s.clients) c.revoked = true;
          for (const a of s.authorizations) a.used = true;
          for (const a of s.approvals)
            if (a.status === 'pending' || a.status === 'approved') a.status = 'denied';
        }
        if (action === 'restore') {
          s.panic = false;
          s.paused = true;
        }
      });
      if (action === 'pause' || action === 'panic') this.executor.cancelAll();
      return json({ updated: true });
    }
    if (action === 'logs.tail') return json({ text: await this.audit.tail() });
    return json({ error: 'Unknown action' }, 400);
  }
}
