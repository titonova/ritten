import { appendFile, mkdir, readdir, stat, unlink, readFile } from 'node:fs/promises';
import path from 'node:path';
import { bytes, milliseconds, type Config } from '../config/schema.js';
import { randomUUID } from 'node:crypto';
export function redact(value: unknown): unknown {
  if (typeof value === 'string')
    return value
      .replace(/Bearer\s+\S+/gi, 'Bearer [REDACTED]')
      .replace(/(?:sk-[A-Za-z0-9_-]{16,}|rt_[A-Za-z0-9_-]{43})/g, '[REDACTED]');
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object')
    return Object.fromEntries(
      Object.entries(value).map(([k, v]) => [
        k,
        /password|passphrase|token|secret|api.?key|authorization|cookie/i.test(k)
          ? '[REDACTED]'
          : redact(v),
      ]),
    );
  return value;
}
export class AuditLog {
  private queue: Promise<unknown> = Promise.resolve();
  constructor(
    readonly directory: string,
    private config: Config['logging'],
  ) {}
  async record(event: Record<string, unknown>): Promise<void> {
    const op = this.queue.then(async () => {
      await mkdir(this.directory, { recursive: true, mode: 0o700 });
      const entries = (await readdir(this.directory))
        .filter((f) => /^audit-[\d-]+-[a-f0-9-]+\.jsonl$/.test(f))
        .sort();
      const now = Date.now();
      for (const f of entries)
        if (
          now - (await stat(path.join(this.directory, f))).mtimeMs >
          milliseconds(this.config.retention)
        )
          await unlink(path.join(this.directory, f));
      let filename = entries.at(-1);
      if (
        !filename ||
        (await stat(path.join(this.directory, filename))
          .then((s) => s.size >= bytes(this.config.max_file_size))
          .catch(() => true))
      )
        filename = `audit-${now}-${randomUUID()}.jsonl`;
      const argumentsValue =
        event.arguments && typeof event.arguments === 'object'
          ? {
              ...event.arguments,
              ...(Object.hasOwn(event.arguments, 'content') ? { content: '[REDACTED]' } : {}),
              ...(Object.hasOwn(event.arguments, 'old_text') ? { old_text: '[REDACTED]' } : {}),
              ...(Object.hasOwn(event.arguments, 'new_text') ? { new_text: '[REDACTED]' } : {}),
            }
          : event.arguments;
      let payload = JSON.stringify(
        redact({
          time: new Date().toISOString(),
          eventId: randomUUID(),
          ...event,
          ...(Object.hasOwn(event, 'arguments') ? { arguments: argumentsValue } : {}),
        }),
      );
      if (Buffer.byteLength(payload) > bytes(this.config.result_limit))
        payload = JSON.stringify({
          time: new Date().toISOString(),
          event: event.event,
          truncated: true,
        });
      await appendFile(path.join(this.directory, filename), `${payload}\n`, {
        mode: 0o600,
        flush: true,
      });
    });
    this.queue = op.catch(() => {});
    await op;
  }
  async tail(): Promise<string> {
    const files = (await readdir(this.directory).catch(() => [] as string[]))
      .filter((f) => /^audit-.*\.jsonl$/.test(f))
      .sort();
    const last = files.at(-1);
    if (!last) return '';
    const contents = await readFile(path.join(this.directory, last), 'utf8');
    return contents.split('\n').slice(-101).join('\n');
  }
}
