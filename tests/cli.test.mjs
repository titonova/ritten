import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const cli = new URL('../dist/cli/index.js', import.meta.url).pathname;
const run = (...args) =>
  spawnSync(
    process.execPath,
    [decodeURIComponent(cli.replace(/^\/(?:([A-Za-z]:))/, '$1')), ...args],
    { encoding: 'utf8' },
  );
test('help describes current availability', () => {
  const result = run('--help');
  assert.equal(result.status, 0);
  assert.match(result.stdout, /under development/);
});
test('version matches package metadata', () => {
  const result = run('--version');
  assert.equal(
    result.stdout.trim(),
    JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version,
  );
});
test('unknown commands fail', () => assert.equal(run('not-a-command').status, 2));
