import { z } from 'zod';
export const duration = z
  .string()
  .regex(/^[1-9]\d*(ms|s|m|h|d)$/)
  .refine((v) => {
    try {
      return Number.isSafeInteger(milliseconds(v)) && milliseconds(v) <= 2592000000;
    } catch {
      return false;
    }
  }, 'Duration must be no more than 30 days');
export const size = z
  .string()
  .regex(/^[1-9]\d*(B|KB|MB)$/)
  .refine((v) => {
    try {
      return Number.isSafeInteger(bytes(v)) && bytes(v) <= 1073741824;
    } catch {
      return false;
    }
  }, 'Size must be no more than 1GB');
export function milliseconds(value: string): number {
  const m = /^(\d+)(ms|s|m|h|d)$/.exec(value);
  if (!m) throw new Error('Invalid duration');
  return Number(m[1]) * { ms: 1, s: 1000, m: 60000, h: 3600000, d: 86400000 }[m[2]!]!;
}
export function bytes(value: string): number {
  const m = /^(\d+)(B|KB|MB)$/.exec(value);
  if (!m) throw new Error('Invalid size');
  return Number(m[1]) * { B: 1, KB: 1024, MB: 1048576 }[m[2]!]!;
}
const strings = z.array(z.string().min(1)).min(1);
const rule = z.strictObject({
  id: z.string().min(1),
  match: z.strictObject({
    tools: strings,
    clients: strings.optional(),
    paths: strings.optional(),
    domains: strings.optional(),
    commands: strings.optional(),
    executables: strings.optional(),
    tasks: strings.optional(),
  }),
  decision: z.enum(['allow', 'ask', 'deny']),
});
export const configSchema = z
  .strictObject({
    version: z.literal(1),
    server: z.strictObject({
      host: z.literal('127.0.0.1'),
      port: z.number().int().min(1).max(65534),
      owner_port: z.number().int().min(1).max(65535).default(7338),
      public_url: z.string().url().nullable().default(null),
      request_timeout: duration.default('30s'),
      result_limit: size.default('200KB'),
    }),
    owner: z
      .strictObject({ instructions: z.string().max(16000).default('') })
      .default({ instructions: '' }),
    external_servers: z
      .array(
        z.strictObject({
          name: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/),
          command: z.string().min(1),
          args: z.array(z.string()).default([]),
          working_directory: z.string().min(1),
          environment: z.record(z.string(), z.string()).default({}),
          enabled: z.boolean().default(false),
          startup_timeout: duration.default('10s'),
          call_timeout: duration.default('30s'),
        }),
      )
      .default([]),
    toolsets: z
      .strictObject({
        directories: z.array(z.string()).default([]),
        enabled: z.array(z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/)).default(['ritten']),
        settings: z
          .strictObject({
            filesystem: z
              .strictObject({
                roots: z.array(
                  z.strictObject({
                    path: z.string().min(1),
                    access: z.enum(['read-only', 'read-write']),
                  }),
                ),
                follow_symlinks: z.literal(false).default(false),
              })
              .default({ roots: [], follow_symlinks: false }),
            web: z
              .strictObject({
                allowed_domains: z.array(z.string()).default([]),
                allow_private_networks: z.literal(false).default(false),
                max_redirects: z.number().int().min(0).max(5).default(5),
              })
              .default({ allowed_domains: [], allow_private_networks: false, max_redirects: 5 }),
            process: z
              .strictObject({
                max_concurrent: z.number().int().min(1).max(32).default(4),
                default_timeout: duration.default('30s'),
                max_runtime: duration.default('30m'),
                max_output_bytes: z.number().int().min(1024).max(1048576).default(65536),
                tasks: z
                  .record(
                    z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/),
                    z.strictObject({
                      executable: z.string().min(1),
                      args: z.array(z.string().max(16384)).max(128).default([]),
                      cwd: z.string().min(1),
                      timeout: duration.optional(),
                    }),
                  )
                  .default({}),
              })
              .default({
                max_concurrent: 4,
                default_timeout: '30s',
                max_runtime: '30m',
                max_output_bytes: 65536,
                tasks: {},
              }),
          })
          .default({
            filesystem: { roots: [], follow_symlinks: false },
            web: { allowed_domains: [], allow_private_networks: false, max_redirects: 5 },
            process: {
              max_concurrent: 4,
              default_timeout: '30s',
              max_runtime: '30m',
              max_output_bytes: 65536,
              tasks: {},
            },
          }),
      })
      .default({
        directories: [],
        enabled: ['ritten'],
        settings: {
          filesystem: { roots: [], follow_symlinks: false },
          web: { allowed_domains: [], allow_private_networks: false, max_redirects: 5 },
          process: {
            max_concurrent: 4,
            default_timeout: '30s',
            max_runtime: '30m',
            max_output_bytes: 65536,
            tasks: {},
          },
        },
      }),
    notifications: z
      .strictObject({
        windows: z
          .strictObject({
            enabled: z.boolean().default(true),
          })
          .default({ enabled: true }),
      })
      .default({ windows: { enabled: true } }),
    policy: z.strictObject({
      default: z.literal('deny'),
      approval_timeout: duration.default('20s'),
      rules: z.array(rule),
    }),
    logging: z
      .strictObject({
        max_file_size: size.default('25MB'),
        retention: duration.default('30d'),
        result_limit: size.default('32KB'),
        include_results: z.boolean().default(false),
      })
      .default({
        max_file_size: '25MB',
        retention: '30d',
        result_limit: '32KB',
        include_results: false,
      }),
  })
  .superRefine((c, ctx) => {
    if (c.server.port === c.server.owner_port)
      ctx.addIssue({ code: 'custom', message: 'Owner and MCP ports must differ' });
    if (
      milliseconds(c.server.request_timeout) > 300000 ||
      milliseconds(c.policy.approval_timeout) > 300000
    )
      ctx.addIssue({
        code: 'custom',
        message: 'Request and approval timeouts may not exceed five minutes',
      });
    if (milliseconds(c.policy.approval_timeout) >= milliseconds(c.server.request_timeout))
      ctx.addIssue({
        code: 'custom',
        message: 'Approval timeout must fit within the total request timeout',
      });
    if (c.server.public_url) {
      const u = new URL(c.server.public_url);
      if (
        u.protocol !== 'https:' ||
        u.username ||
        u.password ||
        u.search ||
        u.hash ||
        u.pathname !== '/'
      )
        ctx.addIssue({
          code: 'custom',
          message: 'public_url must be an HTTPS origin without credentials or path',
        });
    }
    if (new Set(c.policy.rules.map((r) => r.id)).size !== c.policy.rules.length)
      ctx.addIssue({ code: 'custom', message: 'Policy rule IDs must be unique' });
    if (
      new Set(c.external_servers.map((s) => s.name)).size !== c.external_servers.length ||
      c.external_servers.some((s) =>
        ['ritten', 'filesystem', 'coding', 'web', 'raw_shell', 'process'].includes(s.name),
      )
    )
      ctx.addIssue({
        code: 'custom',
        message: 'External server names must be unique and cannot replace built-ins',
      });
  });
export type Config = z.infer<typeof configSchema>;
export const defaultConfig = configSchema.parse({
  version: 1,
  server: { host: '127.0.0.1', port: 7337 },
  policy: { default: 'deny', rules: [] },
});
