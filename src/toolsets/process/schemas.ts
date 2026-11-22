import { z } from 'zod';
const run = {
  executable: z.string().min(1).max(4096),
  args: z.array(z.string().max(16384)).max(128).default([]),
  cwd: z.string().min(1).max(4096),
  timeout_ms: z.number().int().min(100).max(1800000).optional(),
  max_output_bytes: z.number().int().min(1024).max(1048576).optional(),
  env: z.record(z.string(), z.string()).default({}),
};
export const processDefinitions = {
  'process.list_allowed': {
    schema: z.strictObject({}),
    readOnly: true,
    description:
      'List executable and configured task permissions effective for the authenticated client only.',
  },
  'process.run': {
    schema: z.strictObject(run),
    readOnly: false,
    description:
      'Run a canonical native executable with argument-array spawning in an authorized working folder; bounded output and runtime apply.',
  },
  'process.run_task': {
    schema: z.strictObject({ task: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/) }),
    readOnly: false,
    description:
      'Run a named task configured by the owner; executable, arguments, folder, and timeout cannot be overridden.',
  },
} as const;
