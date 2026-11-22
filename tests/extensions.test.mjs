import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { discover, loadCustom } from '../dist/toolsets/loader.js';
import { loadExternal } from '../dist/toolsets/external.js';
import { configSchema } from '../dist/config/schema.js';

test('discovery never imports disabled code and built-ins cannot be shadowed', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'ritten-loader-'));
  try {
    await mkdir(path.join(dir, 'notes'));
    await mkdir(path.join(dir, 'filesystem'));
    await writeFile(path.join(dir, 'notes', 'search.js'), 'throw Error("must not execute");');
    const found = await discover([dir]);
    assert.ok(found.has('notes'));
    assert.equal(found.has('filesystem'), false);
    assert.deepEqual(await loadCustom([dir], []), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test('enabled TypeScript custom tools load with stable fingerprints and ignore helpers', async () => {
  // Keep this fixture under the project so its imports resolve the pinned runtime dependencies.
  const dir = await mkdtemp(path.join(process.cwd(), '.toolset-test-'));
  try {
    await mkdir(path.join(dir, 'notes'));
    await writeFile(path.join(dir, 'notes', '_shared.ts'), 'export const prefix="found";');
    await writeFile(
      path.join(dir, 'notes', 'search.ts'),
      'import {z} from "zod"; import {prefix} from "./_shared.ts"; export default {description:"Search",inputSchema:z.object({query:z.string()}),readOnly:true,async run(input){return {text:prefix+input.query};}};',
    );
    const a = await loadCustom([dir], ['notes']);
    const b = await loadCustom([dir], ['notes']);
    assert.equal(a.length, 1);
    assert.equal(a[0].fingerprint, b[0].fingerprint);
    assert.deepEqual(await a[0].definition.run({ query: 'x' }, {}), { text: 'foundx' });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test('external stdio tools use official client, schemas, and explicit environment', async () => {
  const dir = await mkdtemp(path.join(process.cwd(), '.external-test-'));
  let external;
  try {
    const script = path.join(dir, 'server.mjs');
    await writeFile(
      script,
      `import {McpServer} from '@modelcontextprotocol/server';import {StdioServerTransport} from '@modelcontextprotocol/server/stdio';import {z} from 'zod';const server=new McpServer({name:'fixture',version:'1'});server.registerTool('echo',{description:'Echo',inputSchema:z.object({text:z.string()})},async input=>({content:[{type:'text',text:input.text}]}));await server.connect(new StdioServerTransport());`,
    );
    const config = configSchema.parse({
      version: 1,
      server: { host: '127.0.0.1', port: 7337 },
      policy: { default: 'deny', rules: [] },
      external_servers: [
        {
          name: 'fixture',
          command: process.execPath,
          args: [script],
          working_directory: dir,
          enabled: true,
        },
      ],
    });
    external = await loadExternal(config);
    assert.equal(external.tools[0].name, 'fixture.echo');
    const result = await external.tools[0].definition.run(
      { text: 'hello' },
      { signal: new AbortController().signal },
    );
    assert.equal(result.content[0].text, 'hello');
  } finally {
    if (external) await external.close();
    await rm(dir, { recursive: true, force: true });
  }
});
