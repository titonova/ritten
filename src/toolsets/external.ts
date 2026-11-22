import { Client } from '@modelcontextprotocol/client';
import {
  StdioClientTransport,
  DEFAULT_INHERITED_ENV_VARS,
} from '@modelcontextprotocol/client/stdio';
import { z } from 'zod';
import type { Config } from '../config/schema.js';
import { milliseconds } from '../config/schema.js';
import type { LoadedTool } from './loader.js';
import { hash } from '../auth/credentials.js';
import path from 'node:path';

export async function loadExternal(
  config: Config,
): Promise<{ tools: LoadedTool[]; close(): Promise<void> }> {
  const tools: LoadedTool[] = [];
  const clients: Client[] = [];
  try {
    for (const entry of config.external_servers.filter((s) => s.enabled)) {
      if (!path.isAbsolute(entry.command) || !path.isAbsolute(entry.working_directory))
        throw new Error('External commands and working directories must be absolute');
      const env = {
        ...Object.fromEntries(DEFAULT_INHERITED_ENV_VARS.map((k) => [k, undefined])),
        ...entry.environment,
      } as Record<string, string>;
      const transport = new StdioClientTransport({
        command: entry.command,
        args: entry.args,
        env,
        cwd: entry.working_directory,
        stderr: 'pipe',
        maxBufferSize: 1048576,
      });
      // Drain stderr without reflecting arbitrary trusted process output to the public client.
      transport.stderr?.on('data', () => {});
      const client = new Client({ name: 'Ritten-external', version: '0.0.0' });
      clients.push(client);
      await client.connect(transport, { timeout: milliseconds(entry.startup_timeout) });
      const listed = await client.listTools();
      for (const tool of listed.tools) {
        if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(tool.name))
          throw new Error('External tool name is unsupported');
        const schema = z.fromJSONSchema(tool.inputSchema as Parameters<typeof z.fromJSONSchema>[0]);
        tools.push({
          name: `${entry.name}.${tool.name}`,
          fingerprint: hash(
            JSON.stringify({
              entry: { ...entry, environment: Object.keys(entry.environment) },
              tool,
            }),
          ),
          definition: {
            description: tool.description ?? tool.name,
            inputSchema: schema,
            readOnly: tool.annotations?.readOnlyHint ?? false,
            async run(input, context) {
              const result = await client.callTool(
                { name: tool.name, arguments: input as Record<string, unknown> },
                { signal: context.signal, timeout: milliseconds(entry.call_timeout) },
              );
              if (result.isError) throw new Error('External tool returned an error');
              return result;
            },
          },
        });
      }
    }
    return {
      tools,
      async close() {
        await Promise.allSettled(clients.map((c) => c.close()));
      },
    };
  } catch (e) {
    await Promise.allSettled(clients.map((c) => c.close()));
    throw e;
  }
}
