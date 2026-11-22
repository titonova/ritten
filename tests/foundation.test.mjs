import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configSchema, defaultConfig } from '../dist/config/schema.js';
import { loadConfig } from '../dist/config/loader.js';
import { evaluatePolicy, matches } from '../dist/policy/engine.js';

test('configuration rejects unknown fields, non-loopback host, and non-deny defaults', () => {
  assert.equal(configSchema.safeParse(defaultConfig).success, true);
  assert.equal(configSchema.safeParse({ ...defaultConfig, extra: true }).success, false);
  assert.equal(
    configSchema.safeParse({ ...defaultConfig, server: { host: '0.0.0.0', port: 7337 } }).success,
    false,
  );
  assert.equal(
    configSchema.safeParse({ ...defaultConfig, policy: { default: 'allow', rules: [] } }).success,
    false,
  );
});
test('Windows approval notifications default on and may be disabled explicitly', () => {
  assert.equal(defaultConfig.notifications.windows.enabled, true);
  const off = configSchema.parse({
    ...defaultConfig,
    notifications: { windows: { enabled: false } },
  });
  assert.equal(off.notifications.windows.enabled, false);
  assert.equal(
    configSchema.safeParse({ ...defaultConfig, notifications: { windows: { enabled: 'yes' } } })
      .success,
    false,
  );
});

test('YAML duplicate keys are rejected', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ritten-test-'));
  try {
    const file = join(dir, 'config.yaml');
    await writeFile(file, 'version: 1\nversion: 1\n');
    await assert.rejects(loadConfig(file));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test('policy is first-match, client scoped, and defaults to deny', () => {
  const policy = {
    default: 'deny',
    rules: [
      { id: 'block', match: { tools: ['filesystem.delete'] }, decision: 'deny' },
      { id: 'read', match: { tools: ['filesystem.*'], clients: ['owner'] }, decision: 'ask' },
    ],
  };
  assert.deepEqual(evaluatePolicy(policy, { tool: 'filesystem.delete', client: 'owner' }), {
    decision: 'deny',
    ruleId: 'block',
  });
  assert.deepEqual(evaluatePolicy(policy, { tool: 'filesystem.read_file', client: 'owner' }), {
    decision: 'ask',
    ruleId: 'read',
  });
  assert.deepEqual(evaluatePolicy(policy, { tool: 'filesystem.read_file', client: 'other' }), {
    decision: 'deny',
  });
  assert.deepEqual(evaluatePolicy(policy, { tool: 'filesystem', client: 'owner' }), {
    decision: 'deny',
  });
});
test('tool patterns are case sensitive; path folding is explicit', () => {
  assert.equal(matches('filesystem.*', 'Filesystem.read_file'), false);
  assert.equal(matches('C:/Projects/**', 'c:/projects/file.txt', true), true);
  assert.equal(matches('C:/Projects/**', 'c:/projects/file.txt'), false);
});
