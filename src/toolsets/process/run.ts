import { spawn } from 'node:child_process';
import path from 'node:path';
import { realpath, stat } from 'node:fs/promises';
import { milliseconds, type Config } from '../../config/schema.js';

export interface ProcessRequest {
  executable: string;
  args: string[];
  cwd: string;
  timeout_ms?: number;
  max_output_bytes?: number;
  env?: Record<string, string>;
}

export async function resolveExecutable(input: string): Promise<string> {
  if (!input || input.includes('\0')) throw new Error('Invalid executable path');
  const windows = process.platform === 'win32';
  const extensions = windows ? ['', '.exe', '.com'] : [''];
  const roots = windows
    ? [
        path.dirname(process.execPath),
        path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32'),
      ]
    : ['/usr/bin', '/bin', path.dirname(process.execPath)];
  const candidates = path.isAbsolute(input)
    ? [input]
    : roots.flatMap((root) => extensions.map((extension) => path.join(root, input + extension)));
  for (const candidate of candidates) {
    try {
      const canonical = await realpath(candidate);
      if (!(await stat(canonical)).isFile()) continue;
      if (windows && !/\.(exe|com)$/i.test(canonical))
        throw new Error('Only native executables are supported; shell scripts are not accepted');
      return canonical;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT' && code !== 'ENOTDIR') throw error;
    }
  }
  throw new Error(
    'Executable not found; provide its absolute path or use an executable in the trusted system search paths',
  );
}

export async function runProcess(
  input: ProcessRequest,
  signal: AbortSignal,
  config: Config,
): Promise<Record<string, unknown>> {
  const executable = await resolveExecutable(input.executable);
  const settings = config.toolsets.settings.process;
  const timeout = Math.min(
    input.timeout_ms ?? milliseconds(settings.default_timeout),
    milliseconds(settings.max_runtime),
  );
  const cap = Math.min(
    input.max_output_bytes ?? settings.max_output_bytes,
    settings.max_output_bytes,
  );
  const env: NodeJS.ProcessEnv =
    process.platform === 'win32'
      ? {
          SystemRoot: process.env.SystemRoot ?? 'C:\\Windows',
          PATH: [
            path.dirname(process.execPath),
            path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32'),
          ].join(path.delimiter),
        }
      : { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' };
  for (const [key, value] of Object.entries(input.env ?? {})) {
    if (
      !/^(CI|NODE_ENV|LANG|LC_ALL|TZ|TERM)$/.test(key) ||
      value.length > 1024 ||
      value.includes('\0')
    )
      throw new Error(`Environment override is not allowed: ${key}`);
    env[key] = value;
  }
  const child = spawn(executable, input.args, {
    cwd: input.cwd,
    env,
    shell: false,
    windowsHide: true,
    detached: process.platform !== 'win32',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  let stderr: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  let capturedBytes = 0;
  let truncated = false;
  const collect = (channel: 'stdout' | 'stderr', chunk: Buffer): void => {
    const remaining = Math.max(0, cap - capturedBytes);
    const kept = chunk.subarray(0, remaining);
    capturedBytes += kept.length;
    if (channel === 'stdout') stdout = Buffer.concat([stdout, kept]);
    else stderr = Buffer.concat([stderr, kept]);
    if (kept.length < chunk.length) truncated = true;
  };
  child.stdout.on('data', (chunk: Buffer) => collect('stdout', chunk));
  child.stderr.on('data', (chunk: Buffer) => collect('stderr', chunk));
  const started = Date.now();
  let timedOut = false;
  let cancelled = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const terminate = (force = true): void => {
    if (!child.pid) return;
    if (process.platform === 'win32') {
      const killer = spawn(
        path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'taskkill.exe'),
        ['/PID', String(child.pid), '/T', ...(force ? ['/F'] : [])],
        { windowsHide: true, stdio: 'ignore' },
      );
      let fallback: ReturnType<typeof setTimeout> | undefined = setTimeout(() => {
        try {
          child.kill(force ? 'SIGKILL' : 'SIGTERM');
        } catch {
          /* process already exited */
        }
      }, 250);
      const finishKill = (code: number | null): void => {
        if (fallback) clearTimeout(fallback);
        fallback = undefined;
        if (code !== 0) {
          try {
            child.kill(force ? 'SIGKILL' : 'SIGTERM');
          } catch {
            /* process already exited */
          }
        }
      };
      killer.once('error', () => finishKill(null));
      killer.once('exit', finishKill);
    } else {
      try {
        process.kill(-child.pid, force ? 'SIGKILL' : 'SIGTERM');
      } catch {
        try {
          child.kill(force ? 'SIGKILL' : 'SIGTERM');
        } catch {
          /* process already exited */
        }
      }
    }
  };
  const cancel = () => {
    cancelled = true;
    terminate(true);
  };
  signal.addEventListener('abort', cancel, { once: true });
  timer = setTimeout(() => {
    timedOut = true;
    terminate(true);
  }, timeout);
  const result = await new Promise<{ code: number | null; error?: string }>((resolve) => {
    child.once('error', (error) => resolve({ code: null, error: error.message }));
    child.once('close', (code) => resolve({ code }));
  }).finally(() => {
    if (timer) clearTimeout(timer);
    signal.removeEventListener('abort', cancel);
  });
  return {
    executable,
    cwd: input.cwd,
    exit_code: result.code,
    status: result.error ? 'failed' : timedOut ? 'timed_out' : cancelled ? 'cancelled' : 'exited',
    ...(result.error ? { error: result.error } : {}),
    stdout: stdout.toString('utf8'),
    stderr: stderr.toString('utf8'),
    duration_ms: Date.now() - started,
    output_truncated: truncated,
    timeout_ms: timeout,
  };
}
