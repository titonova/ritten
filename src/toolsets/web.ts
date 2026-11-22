import { lookup } from 'node:dns/promises';
import { request } from 'node:https';
import ipaddr from 'ipaddr.js';
import type { Config } from '../config/schema.js';

export async function webFetch(
  config: Config,
  input: string,
  signal: AbortSignal,
  checkDomain: (domain: string) => boolean = () => true,
): Promise<unknown> {
  let current = new URL(input);
  for (let step = 0; step <= config.toolsets.settings.web.max_redirects; step++) {
    signal.throwIfAborted();
    if (
      current.protocol !== 'https:' ||
      current.username ||
      current.password ||
      (current.port && current.port !== '443') ||
      !config.toolsets.settings.web.allowed_domains.includes(current.hostname) ||
      !checkDomain(current.hostname)
    )
      throw new Error('Web destination denied');
    const addresses = await lookup(current.hostname, { all: true, verbatim: true });
    if (
      !addresses.length ||
      addresses.some(
        (a) => !ipaddr.isValid(a.address) || ipaddr.parse(a.address).range() !== 'unicast',
      )
    )
      throw new Error('Non-public address denied');
    const pinned = addresses[0]!;
    const response = await new Promise<{
      status: number;
      location?: string;
      text: string;
      contentType: string;
    }>((resolve, reject) => {
      const req = request(
        current,
        {
          method: 'GET',
          signal,
          lookup: (_host, options, cb) => {
            if (options.all) cb(null, [pinned]);
            else cb(null, pinned.address, pinned.family);
          },
          headers: {
            'user-agent': 'Ritten/0.0.0',
            accept: 'text/plain, text/html, application/json',
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          let total = 0;
          res.on('data', (chunk: Buffer) => {
            total += chunk.length;
            if (total > 131072) {
              res.destroy(new Error('Web response exceeds 128KB'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('error', reject);
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 500,
              ...(res.headers.location ? { location: res.headers.location } : {}),
              text: Buffer.concat(chunks).toString('utf8'),
              contentType: res.headers['content-type'] ?? '',
            }),
          );
        },
      );
      req.on('error', reject);
      req.end();
    });
    if (response.status >= 300 && response.status < 400 && response.location) {
      current = new URL(response.location, current);
      continue;
    }
    return {
      url: current.href,
      status: response.status,
      contentType: response.contentType,
      text: response.text,
    };
  }
  throw new Error('Redirect limit reached');
}
