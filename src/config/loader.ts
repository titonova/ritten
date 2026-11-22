import { readFile, stat } from 'node:fs/promises';
import { parse } from 'yaml';
import { configSchema, type Config } from './schema.js';

export async function loadConfig(filename: string): Promise<Config> {
  if ((await stat(filename)).size > 1048576) throw new Error('Configuration exceeds 1MB');
  const contents = await readFile(filename, 'utf8');
  const config = configSchema.parse(parse(contents, { uniqueKeys: true, maxAliasCount: 20 }));
  if (config.toolsets.enabled.includes('raw_shell'))
    console.warn(
      'Deprecated configuration: raw_shell is no longer advertised. Its permissions are not migrated; configure process.* explicitly.',
    );
  return config;
}
