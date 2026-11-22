import { z } from 'zod';
import { type Config, bytes, milliseconds } from '../config/schema.js';
import { type Credential, StateStore, type Approval } from '../storage/state.js';
import { hash, secret, credentialIsLive } from '../auth/credentials.js';
import { evaluatePolicy, matches } from '../policy/engine.js';
import { authorizePath, normalized, filesystemRun } from '../toolsets/filesystem.js';
import { AuditLog, redact } from '../audit/log.js';
import { webFetch } from '../toolsets/web.js';
import { codingDefinitions, codingRun } from '../toolsets/coding/index.js';
import { processDefinitions } from '../toolsets/process/schemas.js';
import { resolveExecutable, runProcess } from '../toolsets/process/run.js';
import { listAllowedProcess } from '../toolsets/process/allowed.js';
import { notifyWindowsApproval } from '../ui/windows-notifications.js';
import type { LoadedTool } from '../toolsets/loader.js';

const pathInput = z.string().min(1).max(4096);
export const toolDefinitions = {
  ...processDefinitions,
  ...codingDefinitions,
  'ritten.health': {
    schema: z.strictObject({}),
    readOnly: true,
    description: 'Report health, enabled tools, and owner instructions',
  },
  'filesystem.read_file': {
    schema: z.strictObject({
      path: pathInput,
      offset: z.number().int().min(0).default(0),
      length: z.number().int().min(1).max(65536).default(16384),
    }),
    readOnly: true,
    description: 'Read a bounded UTF-8 file chunk',
  },
  'filesystem.list_directory': {
    schema: z.strictObject({ path: pathInput, offset: z.number().int().min(0).default(0) }),
    readOnly: true,
    description: 'List up to 200 directory entries',
  },
  'filesystem.stat': {
    schema: z.strictObject({ path: pathInput }),
    readOnly: true,
    description: 'Read file metadata',
  },
  'filesystem.search': {
    schema: z.strictObject({ path: pathInput, query: z.string().min(1).max(200) }),
    readOnly: true,
    description: 'Bounded recursive filename search without following symlinks',
  },
  'filesystem.write_file': {
    schema: z.strictObject({ path: pathInput, content: z.string().max(65536) }),
    readOnly: false,
    description: 'Create or replace a UTF-8 file after scope/policy checks',
  },
  'filesystem.create_directory': {
    schema: z.strictObject({ path: pathInput }),
    readOnly: false,
    description: 'Create one directory',
  },
  'filesystem.move': {
    schema: z.strictObject({ path: pathInput, destination: pathInput }),
    readOnly: false,
    description: 'Move a file or directory to an unoccupied destination',
  },
  'filesystem.delete': {
    schema: z.strictObject({ path: pathInput }),
    readOnly: false,
    description: 'Delete a file or empty directory',
  },
  'web.fetch': {
    schema: z.strictObject({ url: z.string().url().max(4096) }),
    readOnly: true,
    description: 'Fetch a bounded HTTPS response from an approved public domain',
  },
} as const;
export type ToolName = keyof typeof toolDefinitions;
export class Executor {
  private active = 0;
  private activeProcesses = 0;
  private controllers = new Set<AbortController>();
  constructor(
    readonly config: Config,
    readonly store: StateStore,
    readonly audit: AuditLog,
    readonly custom: LoadedTool[] = [],
  ) {}
  definition(name: string): { schema: z.ZodType; readOnly: boolean; description: string } {
    if (Object.hasOwn(toolDefinitions, name)) return toolDefinitions[name as ToolName];
    const item = this.custom.find((t) => t.name === name);
    if (!item) throw new Error('Unknown tool');
    return {
      schema: item.definition.inputSchema,
      readOnly: item.definition.readOnly ?? false,
      description: item.definition.description,
    };
  }
  list(): string[] {
    return [...Object.keys(toolDefinitions), ...this.custom.map((t) => t.name)].filter((n) =>
      this.config.toolsets.enabled.includes(n.split('.')[0]!),
    );
  }
  cancelAll(): void {
    for (const controller of this.controllers) controller.abort(new Error('Access stopped'));
  }
  private checkCredential(c: Credential): void {
    const s = this.store.snapshot();
    const current = s.credentials.find((x) => x.id === c.id);
    if (
      s.paused ||
      s.panic ||
      !current ||
      !credentialIsLive(current) ||
      s.clients.some((x) => x.id === c.client && x.revoked)
    )
      throw new Error('Access paused or revoked');
  }
  async approval(
    binding: string,
    client: string,
    tool: string,
    args: unknown,
    signal: AbortSignal,
  ): Promise<void> {
    const item: Approval = {
      id: secret().slice(0, 20),
      kind: 'tool',
      client,
      tool,
      arguments: args,
      binding,
      expires: Date.now() + milliseconds(this.config.policy.approval_timeout),
      status: 'pending',
    };
    await this.store.change((s) => {
      if (s.approvals.length > 10000) throw new Error('Approval storage full');
      s.approvals.push(item);
    });
    // The optional WPF prompt is another interface to this SAME approval.
    // Decisions are accepted only while pending, unexpired and outside panic mode.
    const prompt = this.config.notifications.windows.enabled
      ? notifyWindowsApproval(
          {
            id: item.id,
            client,
            tool,
            details: JSON.stringify(redact(args), null, 2),
            expires: item.expires,
            ownerPort: this.config.server.owner_port,
          },
          async (decision) => {
            await this.store.change((s) => {
              if (s.panic) throw new Error('Panic lock active');
              const pending = s.approvals.find((a) => a.id === item.id);
              if (!pending || pending.status !== 'pending' || pending.expires <= Date.now())
                throw new Error('Approval unavailable');
              pending.status = decision === 'approve' ? 'approved' : 'denied';
            });
            await this.audit.record({
              event: 'notification.windows.decision',
              approvalId: item.id,
              decision,
            });
          },
        )
      : null;
    if (prompt) {
      void prompt.done.catch((error: unknown) =>
        this.audit
          .record({
            event: 'notification.windows.failed',
            approvalId: item.id,
            error: error instanceof Error ? error.message.slice(0, 1500) : 'Unknown popup error',
          })
          .catch(() => undefined),
      );
    }
    try {
      while (Date.now() < item.expires) {
        signal.throwIfAborted();
        const approval = this.store.snapshot().approvals.find((x) => x.id === item.id);
        if (approval?.status === 'denied' || !approval) throw new Error('Owner denied approval');
        if (approval.status === 'approved') {
          await this.store.change((s) => {
            const a = s.approvals.find((x) => x.id === item.id)!;
            if (a.status !== 'approved' || a.expires <= Date.now() || a.binding !== binding)
              throw new Error('Stale approval');
            a.status = 'consumed';
          });
          return;
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 100));
      }
      await this.store.change((s) => {
        const a = s.approvals.find((x) => x.id === item.id);
        if (a?.status === 'pending') a.status = 'denied';
      });
      throw new Error('Approval timed out');
    } finally {
      prompt?.close();
    }
  }
  async call(
    name: string,
    raw: unknown,
    c: Credential,
    requestId: string,
    parentSignal?: AbortSignal,
    idempotencyKey: string | null = requestId,
  ): Promise<unknown> {
    const started = Date.now();
    const controller = new AbortController();
    this.controllers.add(controller);
    const timer = setTimeout(
      () => controller.abort(new Error('Call timed out')),
      milliseconds(this.config.server.request_timeout),
    );
    const onAbort = () => controller.abort(new Error('Client cancelled'));
    parentSignal?.addEventListener('abort', onAbort, { once: true });
    if (parentSignal?.aborted) onAbort();
    let counted = false;
    let dedupKey: string | undefined;
    try {
      this.checkCredential(c);
      if (this.active >= 4) throw new Error('Concurrency limit reached');
      this.active++;
      counted = true;
      if (!this.list().includes(name) || !c.tools.some((p) => matches(p, name)))
        throw new Error('Tool not granted');
      const def = this.definition(name);
      const args = def.schema.parse(raw) as Record<string, unknown>;
      const isProcessExecution = name === 'process.run' || name === 'process.run_task';
      let taskName: string | undefined;
      if (name === 'process.run_task') {
        taskName = String(args.task);
        const task = this.config.toolsets.settings.process.tasks[taskName];
        if (!task) throw new Error('Unknown configured process task');
        Object.assign(args, {
          executable: task.executable,
          args: task.args,
          cwd: task.cwd,
          timeout_ms: task.timeout
            ? milliseconds(task.timeout)
            : milliseconds(this.config.toolsets.settings.process.default_timeout),
          max_output_bytes: this.config.toolsets.settings.process.max_output_bytes,
          env: {},
        });
      }
      const requestBinding = hash(
        JSON.stringify({
          name,
          args,
          client: c.client,
          scopes: { tools: c.tools, paths: c.paths, domains: c.domains },
          policy: this.config.policy,
          settings: this.config.toolsets.settings,
          schema: z.toJSONSchema(def.schema),
          fingerprint: this.custom.find((t) => t.name === name)?.fingerprint,
        }),
      );
      if (!def.readOnly && idempotencyKey !== null) {
        if (!idempotencyKey) throw new Error('Mutation requires idempotency key');
        dedupKey = hash(`${c.client}:${idempotencyKey}`);
        const previous = this.store.snapshot().dedup[dedupKey];
        if (previous) {
          if (previous.binding !== requestBinding)
            throw new Error('Identifier reused with different arguments or authority');
          if (previous.status !== 'complete')
            throw new Error('Previous mutation is pending or indeterminate; it will not replay');
          await this.audit.record({
            event: 'tool.deduplicated',
            tool: name,
            client: c.client,
            requestId,
          });
          return previous.result;
        }
      }
      const resources: string[] = [];
      for (const key of ['path', 'destination', 'cwd'])
        if (typeof args[key] === 'string') {
          const resolved = await authorizePath(
            this.config,
            args[key],
            !def.readOnly && key !== 'cwd',
            key === 'destination' ||
              name === 'filesystem.write_file' ||
              name === 'coding.write' ||
              name === 'filesystem.create_directory',
          );
          if (
            !c.paths.some((pattern) =>
              matches(pattern, normalized(resolved), process.platform === 'win32'),
            )
          )
            throw new Error('Credential path scope denied');
          args[key] = resolved;
          resources.push(normalized(resolved));
        }
      const domains = name === 'web.fetch' ? [new URL(String(args.url)).hostname] : [];
      if (domains.some((d) => !c.domains.includes(d)))
        throw new Error('Credential domain scope denied');
      const processExecutable = isProcessExecution
        ? (await resolveExecutable(String(args.executable))).replaceAll('\\', '/')
        : undefined;
      const decision = evaluatePolicy(this.config.policy, {
        tool: name,
        client: c.client,
        paths: resources,
        domains,
        ...(processExecutable ? { executables: [processExecutable] } : {}),
        ...(taskName ? { tasks: [taskName] } : {}),
      });
      if (decision.decision === 'deny') throw new Error('Policy denied');
      if (
        isProcessExecution &&
        (!decision.ruleId ||
          !this.config.policy.rules
            .find((r) => r.id === decision.ruleId)
            ?.match.executables?.some((pattern) =>
              matches(pattern, processExecutable!, process.platform === 'win32'),
            ))
      )
        throw new Error('Process policy must explicitly authorize the canonical executable path');
      if (
        taskName &&
        (!decision.ruleId ||
          !this.config.policy.rules
            .find((r) => r.id === decision.ruleId)
            ?.match.tasks?.includes(taskName))
      )
        throw new Error('Process task policy must explicitly authorize the named task');
      const binding = hash(
        JSON.stringify({ name, args, client: c.client, policy: this.config.policy }),
      );
      if (!def.readOnly && dedupKey) {
        await this.store.change((s) => {
          if (s.dedup[dedupKey!]) throw new Error('Duplicate request in progress');
          if (Object.keys(s.dedup).length > 100000) throw new Error('Deduplication storage full');
          s.dedup[dedupKey!] = { binding: requestBinding, status: 'pending', at: Date.now() };
        });
      }
      await this.audit.record({
        event: 'tool.requested',
        client: c.client,
        tool: name,
        arguments: isProcessExecution
          ? {
              executable: processExecutable,
              cwd: args.cwd,
              task: taskName,
              args: '[REDACTED]',
              env: '[REDACTED]',
            }
          : args,
        decision,
        requestId,
      });
      if (decision.decision === 'ask')
        await this.approval(binding, c.client, name, args, controller.signal);
      this.checkCredential(c);
      controller.signal.throwIfAborted();
      // Re-resolve after waiting; changes to symlink/parent identity invalidate the call.
      for (const key of ['path', 'destination', 'cwd'])
        if (typeof args[key] === 'string') {
          const verified = await authorizePath(
            this.config,
            args[key],
            !def.readOnly && key !== 'cwd',
            key === 'destination' ||
              name === 'filesystem.write_file' ||
              name === 'coding.write' ||
              name === 'filesystem.create_directory',
          );
          if (verified !== args[key]) throw new Error('Path changed during approval');
        }
      let nested = 0;
      if (isProcessExecution) {
        if (this.activeProcesses >= this.config.toolsets.settings.process.max_concurrent)
          throw new Error('Process concurrency limit reached');
        this.activeProcesses++;
      }
      let processCounted = isProcessExecution;
      try {
        const result =
          name === 'process.list_allowed'
            ? await listAllowedProcess(this.config, c)
            : isProcessExecution
              ? await runProcess(
                  {
                    executable: processExecutable!,
                    args: args.args as string[],
                    cwd: String(args.cwd),
                    timeout_ms: Number(
                      args.timeout_ms ??
                        milliseconds(this.config.toolsets.settings.process.default_timeout),
                    ),
                    max_output_bytes: Number(
                      args.max_output_bytes ??
                        this.config.toolsets.settings.process.max_output_bytes,
                    ),
                    env: args.env as Record<string, string>,
                  },
                  controller.signal,
                  this.config,
                )
              : this.custom.some((t) => t.name === name)
                ? await this.custom
                    .find((t) => t.name === name)!
                    .definition.run(args, {
                      signal: controller.signal,
                      log: (message) =>
                        this.audit.record({ event: 'tool.log', tool: name, message }),
                      call: (tool, input) =>
                        this.call(
                          tool,
                          input,
                          c,
                          `${requestId}:nested:${++nested}`,
                          controller.signal,
                          idempotencyKey === null ? null : `${idempotencyKey}:nested:${nested}`,
                        ),
                    })
                : name === 'ritten.health'
                  ? {
                      version: '0.0.0',
                      toolsets: this.config.toolsets.enabled,
                      platform: process.platform,
                      instructions: this.config.owner.instructions,
                      fingerprints: {
                        builtin: hash(
                          JSON.stringify(
                            Object.entries(toolDefinitions).map(([n, d]) => [
                              n,
                              d.description,
                              z.toJSONSchema(d.schema),
                            ]),
                          ),
                        ),
                        ...Object.fromEntries(this.custom.map((t) => [t.name, t.fingerprint])),
                      },
                    }
                  : name === 'web.fetch'
                    ? await webFetch(this.config, String(args.url), controller.signal, (domain) => {
                        const d = evaluatePolicy(this.config.policy, {
                          tool: name,
                          client: c.client,
                          domains: [domain],
                        });
                        // Redirects cannot obtain fresh authority or a new implicit approval.
                        return (
                          c.domains.includes(domain) &&
                          d.ruleId === decision.ruleId &&
                          d.decision === decision.decision
                        );
                      })
                    : name.startsWith('coding.')
                      ? await codingRun(name, args, controller.signal, async (target) => {
                          const resolved = await authorizePath(this.config, target, false);
                          const resource = normalized(resolved);
                          if (
                            !c.paths.some((p) => matches(p, resource, process.platform === 'win32'))
                          )
                            return false;
                          const child = evaluatePolicy(this.config.policy, {
                            tool: name,
                            client: c.client,
                            paths: [resource],
                          });
                          return (
                            child.decision === 'allow' ||
                            (child.decision === 'ask' &&
                              child.ruleId === decision.ruleId &&
                              decision.decision === 'ask')
                          );
                        })
                      : await filesystemRun(
                          name.slice('filesystem.'.length),
                          args,
                          controller.signal,
                        );
        const safe = redact(result);
        const text = JSON.stringify(safe);
        const bounded =
          Buffer.byteLength(text) <= bytes(this.config.server.result_limit)
            ? safe
            : {
                truncated: true,
                originalBytes: Buffer.byteLength(text),
                returnedBytes: 0,
                message: 'Request a smaller chunk',
              };
        await this.audit.record({
          event: 'tool.completed',
          tool: name,
          client: c.client,
          requestId,
          durationMs: Date.now() - started,
          cancelled: controller.signal.aborted,
          ...(this.config.logging.include_results ? { result: bounded } : {}),
        });
        if (dedupKey)
          await this.store.change((s) => {
            s.dedup[dedupKey!] = {
              binding: requestBinding,
              status: 'complete',
              result: bounded,
              at: Date.now(),
            };
          });
        return bounded;
      } finally {
        if (processCounted) {
          this.activeProcesses--;
          processCounted = false;
        }
      }
    } catch (e) {
      await this.audit.record({
        event: 'tool.failed',
        tool: name,
        client: c.client,
        requestId,
        durationMs: Date.now() - started,
        error: e instanceof Error ? e.message : 'Execution error',
      });
      throw e;
    } finally {
      clearTimeout(timer);
      parentSignal?.removeEventListener('abort', onAbort);
      this.controllers.delete(controller);
      if (counted) this.active--;
    }
  }
}
