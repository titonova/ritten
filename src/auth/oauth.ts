import { z } from 'zod';
import { hash, secret, createCredential, credentialIsLive } from './credentials.js';
import type { Config } from '../config/schema.js';
import { StateStore } from '../storage/state.js';
import { normalized } from '../toolsets/filesystem.js';

export const json = (value: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
function validRedirect(value: string): boolean {
  try {
    const u = new URL(value);
    return (
      !u.hash &&
      !u.username &&
      !u.password &&
      (u.protocol === 'https:' ||
        (u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)))
    );
  } catch {
    return false;
  }
}
const registration = z.strictObject({
  client_name: z.string().min(1).max(100).default('MCP client'),
  redirect_uris: z.array(z.string().url().refine(validRedirect)).min(1).max(10),
  application_type: z.enum(['web', 'native']).default('web'),
  scope: z.literal('mcp').optional(),
  token_endpoint_auth_method: z.literal('none').default('none'),
  grant_types: z.array(z.enum(['authorization_code', 'refresh_token'])).optional(),
  response_types: z.array(z.literal('code')).optional(),
});
export class OAuthService {
  readonly issuer: string;
  readonly resource: string;
  constructor(
    readonly config: Config,
    readonly store: StateStore,
  ) {
    this.issuer =
      config.server.public_url?.replace(/\/$/, '') ?? `http://127.0.0.1:${config.server.port}`;
    this.resource = `${this.issuer}/mcp`;
  }
  async handle(request: Request): Promise<Response> {
    const u = new URL(request.url);
    const route = u.pathname;
    if (
      route === '/.well-known/oauth-protected-resource' ||
      route === '/.well-known/oauth-protected-resource/mcp'
    )
      return json({
        resource: this.resource,
        authorization_servers: [this.issuer],
        scopes_supported: ['mcp'],
        bearer_methods_supported: ['header'],
      });
    if (route === '/.well-known/oauth-authorization-server')
      return json({
        issuer: this.issuer,
        authorization_endpoint: `${this.issuer}/oauth/authorize`,
        token_endpoint: `${this.issuer}/oauth/token`,
        registration_endpoint: `${this.issuer}/oauth/register`,
        revocation_endpoint: `${this.issuer}/oauth/revoke`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        token_endpoint_auth_methods_supported: ['none'],
        code_challenge_methods_supported: ['S256'],
        scopes_supported: ['mcp'],
        authorization_response_iss_parameter_supported: true,
      });
    if (this.store.snapshot().panic) return json({ error: 'temporarily_unavailable' }, 503);
    if (route === '/oauth/register' && request.method === 'POST') {
      const body = registration.parse(await request.json());
      const id = secret();
      await this.store.change((s) => {
        if (s.clients.length >= 1000) throw new Error('Registration capacity reached');
        s.clients.push({
          id,
          name: body.client_name,
          redirects: body.redirect_uris,
          revoked: false,
        });
      });
      return json(
        { client_id: id, client_id_issued_at: Math.floor(Date.now() / 1000), ...body },
        201,
      );
    }
    if (route === '/oauth/authorize' && request.method === 'GET') {
      const q = u.searchParams;
      const client = this.store
        .snapshot()
        .clients.find((c) => c.id === q.get('client_id') && !c.revoked);
      if (
        !client ||
        !client.redirects.includes(q.get('redirect_uri') ?? '') ||
        q.get('response_type') !== 'code' ||
        q.get('code_challenge_method') !== 'S256' ||
        !/^[A-Za-z0-9_-]{43}$/.test(q.get('code_challenge') ?? '') ||
        q.get('resource') !== this.resource ||
        (q.get('scope') && q.get('scope') !== 'mcp') ||
        (q.get('state')?.length ?? 0) > 2048
      )
        return json({ error: 'invalid_request' }, 400);
      const id = secret();
      const approval = secret().slice(0, 20);
      const expires = Date.now() + 300000;
      await this.store.change((s) => {
        if (s.authorizations.length >= 10000) throw new Error('Authorization capacity reached');
        s.approvals.push({
          id: approval,
          kind: 'oauth',
          client: client.id,
          tool: 'oauth.connect',
          arguments: { name: client.name, redirect_uri: q.get('redirect_uri'), scope: 'mcp' },
          binding: id,
          expires,
          status: 'pending',
        });
        s.authorizations.push({
          id,
          client: client.id,
          redirect: q.get('redirect_uri')!,
          challenge: q.get('code_challenge')!,
          state: q.get('state') ?? '',
          scope: 'mcp',
          resource: this.resource,
          expires,
          approval,
          codeHash: null,
          used: false,
        });
      });
      return new Response(
        `<!doctype html><meta charset="utf-8"><title>Ritten authorization</title><h1>Approve locally</h1><p>Open the Ritten owner console or run ritten approvals list on your machine. This page refreshes while waiting.</p><p><a href="/oauth/poll?id=${id}">Continue after approval</a></p><meta http-equiv="refresh" content="2;url=/oauth/poll?id=${id}">`,
        {
          headers: {
            'content-type': 'text/html',
            'cache-control': 'no-store',
            'referrer-policy': 'no-referrer',
            'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'",
          },
        },
      );
    }
    if (route === '/oauth/poll' && request.method === 'GET') {
      const a = this.store.snapshot().authorizations.find((a) => a.id === u.searchParams.get('id'));
      if (
        !a ||
        a.expires <= Date.now() ||
        a.used ||
        a.codeHash ||
        this.store.snapshot().clients.some((c) => c.id === a.client && c.revoked)
      )
        return json({ error: 'invalid_request' }, 400);
      const approval = this.store.snapshot().approvals.find((x) => x.id === a.approval);
      if (approval?.status === 'pending')
        return new Response(
          '<meta http-equiv="refresh" content="2"><h1>Waiting for local approval</h1>',
          {
            headers: {
              'content-type': 'text/html',
              'cache-control': 'no-store',
              'referrer-policy': 'no-referrer',
            },
          },
        );
      if (approval?.status !== 'approved') return json({ error: 'access_denied' }, 403);
      const code = secret();
      await this.store.change((s) => {
        const item = s.authorizations.find((x) => x.id === a.id)!;
        const ap = s.approvals.find((x) => x.id === a.approval)!;
        if (item.codeHash || ap.status !== 'approved' || ap.expires <= Date.now())
          throw new Error('Stale authorization');
        item.codeHash = hash(code);
        ap.status = 'consumed';
      });
      const redirect = new URL(a.redirect);
      redirect.searchParams.set('code', code);
      redirect.searchParams.set('state', a.state);
      redirect.searchParams.set('iss', this.issuer);
      return new Response(null, {
        status: 302,
        headers: {
          location: redirect.href,
          'cache-control': 'no-store',
          'referrer-policy': 'no-referrer',
        },
      });
    }
    if (route === '/oauth/token' && request.method === 'POST') {
      const body = new URLSearchParams(await request.text());
      const client = body.get('client_id') ?? '';
      if (!['authorization_code', 'refresh_token'].includes(body.get('grant_type') ?? ''))
        return json({ error: 'unsupported_grant_type' }, 400);
      const result = await this.store.change((s) => {
        const now = Date.now();
        let family = secret();
        if (
          s.panic ||
          !s.clients.some((c) => c.id === client && !c.revoked) ||
          body.get('resource') !== this.resource ||
          (body.get('scope') && body.get('scope') !== 'mcp') ||
          s.credentials.length >= 99998
        )
          return null;
        if (body.get('grant_type') === 'authorization_code') {
          const verifier = body.get('code_verifier') ?? '';
          const challenge = Buffer.from(hash(verifier), 'hex').toString('base64url');
          const a = s.authorizations.find((a) => a.codeHash === hash(body.get('code') ?? ''));
          if (
            !a ||
            a.used ||
            a.expires <= now ||
            a.client !== client ||
            a.redirect !== body.get('redirect_uri') ||
            a.resource !== this.resource ||
            a.challenge !== challenge ||
            !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)
          )
            return null;
          a.used = true;
        } else {
          const previous = s.credentials.find(
            (c) =>
              c.hash === hash(body.get('refresh_token') ?? '') &&
              c.kind === 'refresh' &&
              c.client === client,
          );
          if (!previous) return null;
          if (previous.revoked) {
            for (const c of s.credentials) if (c.family === previous.family) c.revoked = true;
            return null;
          }
          if (!credentialIsLive(previous, now)) return null;
          previous.revoked = true;
          family = previous.family;
        }
        const options = {
          name: 'OAuth',
          client,
          tools: ['*'],
          paths: this.config.toolsets.settings.filesystem.roots.flatMap((r) => [
            normalized(r.path).replace(/\/$/, ''),
            `${normalized(r.path).replace(/\/$/, '')}/**`,
          ]),
          domains: this.config.toolsets.settings.web.allowed_domains,
          family,
        };
        const access = createCredential({ ...options, kind: 'access', lifetime: 900000 });
        const refresh = createCredential({ ...options, kind: 'refresh', lifetime: 2592000000 });
        s.credentials.push(access.credential, refresh.credential);
        return {
          access_token: access.token,
          token_type: 'Bearer',
          expires_in: 900,
          refresh_token: refresh.token,
          scope: 'mcp',
        };
      });
      return result ? json(result) : json({ error: 'invalid_grant' }, 400);
    }
    if (route === '/oauth/revoke' && request.method === 'POST') {
      const body = new URLSearchParams(await request.text());
      await this.store.change((s) => {
        const c = s.credentials.find(
          (c) => c.hash === hash(body.get('token') ?? '') && c.client === body.get('client_id'),
        );
        if (c) for (const item of s.credentials) if (item.family === c.family) item.revoked = true;
      });
      return json({});
    }
    return json({ error: 'not_found' }, 404);
  }
}
