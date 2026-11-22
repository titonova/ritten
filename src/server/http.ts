import { createServer, type Server } from 'node:http';
import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { McpServer, createMcpHandler, type ServerContext } from '@modelcontextprotocol/server';
import { toNodeHandler, type NodeIncomingMessageLike } from '@modelcontextprotocol/node';
import type { Config } from '../config/schema.js';
import { bytes, milliseconds } from '../config/schema.js';
import { authenticate, type OwnerVault } from '../auth/credentials.js';
import { OAuthService, json } from '../auth/oauth.js';
import { StateStore } from '../storage/state.js';
import { Executor, toolDefinitions } from '../executor/pipeline.js';
import { AuditLog } from '../audit/log.js';
import { OwnerService } from '../ui/owner.js';
import { loadCustom } from '../toolsets/loader.js';
import { getPaths } from '../app/paths.js';
import path from 'node:path';
import { loadExternal } from '../toolsets/external.js';

export async function startServer(
  config: Config,
  store: StateStore,
  vault: OwnerVault,
  audit: AuditLog,
) {
  const directories = [
    ...(process.env.RITTEN_TOOLSET_PATHS?.split(path.delimiter).filter(Boolean) ?? []),
    ...config.toolsets.directories,
    getPaths().toolsets,
  ];
  const externalNames = config.external_servers.filter((s) => s.enabled).map((s) => s.name);
  const custom = await loadCustom(
    directories,
    config.toolsets.enabled.filter((n) => !externalNames.includes(n)),
  );
  const external = await loadExternal(config);
  if (external.tools.some((t) => custom.some((c) => c.name === t.name))) {
    await external.close();
    throw new Error('Custom and external tool names collide');
  }
  const effective = {
    ...config,
    toolsets: {
      ...config.toolsets,
      enabled: [...new Set([...config.toolsets.enabled, ...externalNames])],
    },
  };
  const executor = new Executor(effective, store, audit, [...custom, ...external.tools]);
  const oauth = new OAuthService(effective, store);
  const owner = new OwnerService(store, vault, executor, audit);
  const rate = new Map<string, { count: number; reset: number }>();
  function limited(key: string, limit: number): boolean {
    const now = Date.now();
    let item = rate.get(key);
    if (!item || item.reset <= now) {
      item = { count: 0, reset: now + 60000 };
      rate.set(key, item);
    }
    if (rate.size > 2000) for (const [k, v] of rate) if (v.reset <= now) rate.delete(k);
    return ++item.count > limit;
  }
  const allowedHosts = new Set([
    '127.0.0.1',
    'localhost',
    ...(config.server.public_url ? [new URL(config.server.public_url).hostname] : []),
  ]);
  const requestContext = new AsyncLocalStorage<{ idempotencyKey: string | null }>();
  const handler = createMcpHandler(
    async (ctx) => {
      const credential = await authenticate(store, ctx.authInfo?.token ?? '');
      const server = new McpServer({ name: 'Ritten', version: '0.0.0' });
      for (const name of executor.list()) {
        const def = executor.definition(name);
        server.registerTool(
          name,
          {
            description: def.description,
            inputSchema: def.schema,
            annotations: {
              readOnlyHint: def.readOnly,
              destructiveHint: !def.readOnly,
              idempotentHint: def.readOnly,
            },
          },
          async (args: unknown, context: ServerContext) => {
            const requestId = randomUUID();
            const idempotencyKey = requestContext.getStore()?.idempotencyKey ?? null;
            try {
              const result = await executor.call(
                name,
                args,
                credential,
                requestId,
                context.mcpReq.signal,
                idempotencyKey === null ? null : `http-idempotency:${idempotencyKey}`,
              );
              return {
                content: [{ type: 'text' as const, text: JSON.stringify(result) }],
                structuredContent:
                  result !== null && typeof result === 'object' && !Array.isArray(result)
                    ? (result as Record<string, unknown>)
                    : { result },
              };
            } catch (e) {
              return {
                isError: true,
                content: [
                  {
                    type: 'text' as const,
                    text: e instanceof Error ? e.message : 'Execution failed',
                  },
                ],
              };
            }
          },
        );
      }
      return server;
    },
    {
      legacy: 'stateless',
      maxRequestBodySize: bytes(config.server.result_limit),
      responseMode: 'json',
    },
  );
  const publicNode = toNodeHandler(
    {
      async fetch(request) {
        const url = new URL(request.url);
        if (
          !allowedHosts.has(url.hostname) ||
          (request.headers.has('origin') &&
            new URL(request.headers.get('origin')!).origin !== oauth.issuer)
        )
          return json({ error: 'Forbidden host/origin' }, 403);
        if (limited('global', 120)) return json({ error: 'Rate limit' }, 429);
        if (
          url.pathname === '/local' ||
          url.searchParams.has('token') ||
          url.searchParams.has('access_token')
        )
          return json({ error: 'Forbidden' }, 403);
        try {
          if (url.pathname !== '/mcp') {
            await audit.record({
              event: 'http.request',
              path: url.pathname,
              method: request.method,
            });
            return await oauth.handle(request);
          }
          const authorization = request.headers.get('authorization') ?? '';
          if (!authorization.startsWith('Bearer ')) throw new Error('Unauthorized');
          const token = authorization.slice(7);
          const c = await authenticate(store, token);
          if (limited(`client:${c.client}`, 60)) return json({ error: 'Rate limit' }, 429);
          const key = request.headers.get('idempotency-key');
          if (key !== null && !/^[A-Za-z0-9._~-]{1,128}$/.test(key))
            return json({ error: 'Invalid idempotency key' }, 400);
          return await requestContext.run({ idempotencyKey: key }, () =>
            handler.fetch(request, {
              authInfo: { token, clientId: c.client, scopes: ['mcp'] },
            }),
          );
        } catch (e) {
          await audit.record({
            event: 'http.rejected',
            path: url.pathname,
            error: e instanceof Error ? e.message : 'Invalid request',
          });
          return url.pathname === '/mcp'
            ? json({ error: 'Unauthorized' }, 401, {
                'www-authenticate': `Bearer resource_metadata="${oauth.issuer}/.well-known/oauth-protected-resource", scope="mcp"`,
              })
            : json({ error: 'invalid_request' }, 400);
        }
      },
    },
    { maxRequestBodySize: bytes(config.server.result_limit) },
  );
  const ownerNode = toNodeHandler(
    {
      async fetch(request) {
        const u = new URL(request.url);
        const expected = `http://127.0.0.1:${config.server.owner_port}`;
        if (
          u.origin !== expected ||
          request.headers.has('forwarded') ||
          request.headers.has('x-forwarded-for') ||
          request.headers.has('x-forwarded-host') ||
          (request.headers.has('origin') && request.headers.get('origin') !== expected)
        )
          return json({ error: 'Forbidden owner origin' }, 403);
        try {
          return await owner.handle(request);
        } catch {
          return json({ error: 'Invalid owner request or operation failed' }, 400);
        }
      },
    },
    { maxRequestBodySize: 65536 },
  );
  const publicServer = createServer((req, res) => {
    void publicNode(req as NodeIncomingMessageLike, res);
  });
  const ownerServer = createServer((req, res) => {
    void ownerNode(req as NodeIncomingMessageLike, res);
  });
  for (const s of [publicServer, ownerServer]) {
    s.requestTimeout = milliseconds(config.server.request_timeout);
    s.headersTimeout = 10000;
    s.maxHeadersCount = 50;
  }
  const listen = (s: Server, port: number) =>
    new Promise<void>((resolve, reject) => {
      s.once('error', reject);
      s.listen(port, '127.0.0.1', () => {
        s.removeListener('error', reject);
        resolve();
      });
    });
  try {
    await listen(ownerServer, config.server.owner_port);
    await listen(publicServer, config.server.port);
  } catch (e) {
    publicServer.close();
    ownerServer.close();
    await handler.close();
    await external.close();
    throw e;
  }
  try {
    await audit.record({ event: 'server.started', port: config.server.port });
  } catch (e) {
    publicServer.closeAllConnections();
    publicServer.close();
    ownerServer.closeAllConnections();
    ownerServer.close();
    await handler.close();
    await external.close();
    throw e;
  }
  let finish: (() => void) | undefined;
  const stopped = new Promise<void>((resolve) => {
    finish = resolve;
  });
  let closing: Promise<void> | undefined;
  const close = () =>
    (closing ??= (async () => {
      executor.cancelAll();
      await handler.close();
      for (const s of [publicServer, ownerServer]) {
        s.closeAllConnections();
        await new Promise<void>((resolve) => s.close(() => resolve()));
      }
      await external.close();
      try {
        await audit.record({ event: 'server.stopped' });
      } finally {
        finish?.();
      }
    })());
  owner.onStop = () => {
    void close().catch(() => console.error('Ritten shutdown failed; inspect local storage'));
  };
  return { executor, close, stopped };
}
