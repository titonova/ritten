import { spawn } from 'node:child_process';
import path from 'node:path';

export async function runShell(
  command: string,
  cwd: string,
  signal: AbortSignal,
): Promise<unknown> {
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const env: NodeJS.ProcessEnv =
      process.platform === 'win32'
        ? {
            SystemRoot: process.env.SystemRoot ?? 'C:\\Windows',
            PATH: path.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32'),
          }
        : { PATH: '/usr/bin:/bin', LANG: 'C.UTF-8' };
    const child = spawn(command, {
      cwd,
      env,
      shell: true,
      windowsHide: true,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let total = 0;
    let truncated = false;
    let terminationFailed = false;
    let stopIssued = false;
    const stop = () => {
      if (!child.pid || stopIssued) return;
      stopIssued = true;
      if (process.platform === 'win32') {
        const killer = spawn(
          path.join(env.SystemRoot!, 'System32', 'taskkill.exe'),
          ['/PID', String(child.pid), '/T', '/F'],
          { windowsHide: true, stdio: 'ignore' },
        );
        killer.on('error', () => {
          terminationFailed = true;
          child.kill();
        });
        killer.on('exit', (code) => {
          if (code !== 0) {
            terminationFailed = true;
            child.kill();
          }
        });
      } else {
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch {
          terminationFailed = true;
          child.kill('SIGKILL');
        }
      }
    };
    const collect = (list: Buffer[]) => (chunk: Buffer) => {
      total += chunk.length;
      if (total <= 131072) list.push(chunk);
      else {
        truncated = true;
        stop();
      }
    };
    child.stdout.on('data', collect(stdout));
    child.stderr.on('data', collect(stderr));
    signal.addEventListener('abort', stop, { once: true });
    if (signal.aborted) stop();
    child.on('error', (e) => {
      signal.removeEventListener('abort', stop);
      reject(e);
    });
    child.on('close', (exitCode, terminationSignal) => {
      signal.removeEventListener('abort', stop);
      resolve({
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
        exitCode,
        terminationSignal,
        durationMs: Date.now() - started,
        cancelled: signal.aborted,
        terminationFailed,
        truncated,
      });
    });
  });
}
