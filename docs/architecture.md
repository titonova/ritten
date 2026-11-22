# Architecture

`cli/index.ts` handles setup, foreground lifecycle, read-only configuration inspection, and authenticated calls to the owner listener. Runtime state is external to the package. `RITTEN_CONFIG` and `RITTEN_DATA_DIR` allow isolated instances.

`server/http.ts` builds two loopback listeners: MCP/OAuth and owner administration. The official SDK's handler owns protocol parsing/version behavior; the Node adapter owns bounded conversion and response streaming. Ritten validates host/origin, applies rate limits, authenticates credentials, and constructs a fresh MCP server for each exchange. No public route dispatches owner actions.

`auth/oauth.ts` owns metadata, public registration, authorization requests, local consent, PKCE exchange, refresh rotation, and revocation. `auth/credentials.ts` owns random opaque credentials, hashed verifiers, bearer lifetime checks, and the native OS credential-store adapter.

`executor/pipeline.ts` is the tool entry point. It validates schemas, checks enabled tools and narrowed credentials, canonicalizes resource arguments, evaluates policy, persists mutation intent, logs the request, waits for a bound one-time approval when needed, rechecks authority/resources, executes, redacts/caps results, logs completion, and persists mutation results. Denials and errors also generate audit events. All built-in tool dispatch runs here.

`toolsets/filesystem.ts` contains resource normalization and bounded typed operations. `toolsets/web.ts` handles HTTPS fetch with DNS validation/pinning. The initial `toolsets/process/run.ts` implements direct native executable calls with argument arrays, explicit executable policy, bounded output, timeout, and cancellation. `toolsets/shell.ts` is legacy code and its tool is no longer advertised.

`storage/state.ts` uses serialized copy-on-write transactions and atomic persisted replacements, protected by an exclusive instance lock. Corrupted/unsupported state fails startup. `audit/log.ts` writes serialized, redacted, capped JSONL events with rotation/retention. `ui/owner.ts` authenticates owner sessions and dispatches approval/credential/access-control actions.

Enabled custom JS/TS toolsets load through `toolsets/loader.ts`; names come from folders/files, disabled code is not imported, and source fingerprints identify changes. `toolsets/external.ts` connects trusted, explicitly configured stdio servers through the official SDK client. Both become namespaced definitions in the same executor. The public `toolkit` export provides definitions and audited, cancellable context calls.

The current executable is an MVP implementation with explicit development limitations. Managed tunnel adapters, platform services, long-running tasks, SQLite, richer named toolkit helpers, and backups belong to the subsequent full-v1 phases and are not represented by empty placeholder implementations.
