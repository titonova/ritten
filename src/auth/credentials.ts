import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { StateStore, Credential } from '../storage/state.js';
export const secret = () => randomBytes(32).toString('base64url');
export const hash = (value: string) => createHash('sha256').update(value).digest('hex');
export function passwordHash(password: string): string {
  const salt = secret();
  return `${salt}:${scryptSync(password, salt, 32).toString('hex')}`;
}
export function passwordMatches(password: string, stored: string): boolean {
  const [salt, expected] = stored.split(':');
  if (!salt || !expected || expected.length !== 64) return false;
  return timingSafeEqual(scryptSync(password, salt, 32), Buffer.from(expected, 'hex'));
}
export interface OwnerVault {
  get(): Promise<string | null>;
  set(value: string): Promise<void>;
}
export async function systemVault(identity: string): Promise<OwnerVault> {
  const { Entry } = await import('@napi-rs/keyring');
  const entry = new Entry('Ritten', hash(identity), { linux: { store: 'secret-service' } });
  return {
    async get() {
      try {
        return entry.getPassword();
      } catch (e) {
        if (/no entry|not found|NoEntry/i.test(String(e))) return null;
        throw e;
      }
    },
    async set(value) {
      entry.setPassword(value);
    },
  };
}
export type CredentialOptions = Pick<
  Credential,
  'name' | 'client' | 'tools' | 'paths' | 'domains' | 'kind'
> & { family?: string; lifetime?: number };
export function createCredential(options: CredentialOptions): {
  token: string;
  credential: Credential;
} {
  const token = `rt_${secret()}`;
  const now = Date.now();
  const { lifetime: _lifetime, ...fields } = options;
  const credential: Credential = {
    ...fields,
    id: secret().slice(0, 20),
    hash: hash(token),
    created: now,
    firstUsed: null,
    lastUsed: null,
    expires: now + (options.lifetime ?? (options.kind === 'bearer' ? 172800000 : 86400000)),
    revoked: false,
    family: options.family ?? secret(),
  };
  return { token, credential };
}
export async function issueCredential(
  store: StateStore,
  options: CredentialOptions,
): Promise<{ token: string; credential: Credential }> {
  const result = createCredential(options);
  await store.change((s) => {
    if (s.panic || s.credentials.length >= 100000)
      throw new Error('Credential issuance unavailable');
    s.credentials.push(result.credential);
  });
  return result;
}
export async function authenticate(
  store: StateStore,
  token: string,
  kind?: Credential['kind'],
): Promise<Credential> {
  if (!token || token.length > 512) throw new Error('Unauthorized');
  return store.change((s) => {
    const c = s.credentials.find((c) => c.hash === hash(token));
    const now = Date.now();
    if (
      !c ||
      !credentialIsLive(c, now) ||
      s.panic ||
      (kind && c.kind !== kind) ||
      (c.kind === 'refresh' && kind !== 'refresh') ||
      s.clients.some((x) => x.id === c.client && x.revoked)
    )
      throw new Error('Unauthorized');
    c.firstUsed ??= now;
    c.lastUsed = now;
    return structuredClone(c);
  });
}
export function credentialIsLive(c: Credential, now = Date.now()): boolean {
  return (
    !c.revoked &&
    c.expires > now &&
    (c.kind !== 'bearer' ||
      !(
        (c.firstUsed === null && now - c.created >= 86400000) ||
        (c.firstUsed !== null && now - c.firstUsed >= 86400000) ||
        (c.lastUsed !== null && now - c.lastUsed >= 3600000)
      ))
  );
}
