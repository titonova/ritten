# Protocol and platform notes

## Protocol

Ritten uses the official TypeScript MCP SDK for HTTP transport and tool invocation. It exposes a Streamable HTTP MCP endpoint and OAuth protected-resource and authorization-server metadata. OAuth supports dynamic public-client registration, authorization code with S256 PKCE, local owner consent, exact redirect matching, resource binding, short-lived access tokens, refresh rotation, and revocation.

Registration accepts `token_endpoint_auth_method: none`, the advertised `mcp` scope, and `application_type` values `web` and `native`. Ritten currently supports dynamic registration; client-ID metadata documents are not implemented.

## Runtime and platforms

Node.js 22 or newer is required. The CI workflow checks Node.js 22 and 24 on Windows, macOS, and Linux. This matrix describes configured checks, not independent certification of every operating-system version or credential-store backend. Ritten relies on the OS credential store for owner authentication; Linux hosts need a persistent Secret Service.

The owner console listens on its own loopback port (7338 by default). Only the MCP listener (7337 by default) should be exposed through an HTTPS tunnel or reverse proxy. Ritten does not manage the external tunnel.

## Execution limits

Filesystem validation and process working-directory checks are not OS-level isolation. Process tools are synchronous and bounded; persistent process sessions, OS resource quotas, long-running MCP Tasks, and process recovery across server restarts are not implemented. See [Security model](security-model.md).

## Specifications

- [Model Context Protocol authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Model Context Protocol transports](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [OAuth 2.0 Dynamic Client Registration (RFC 7591)](https://www.rfc-editor.org/rfc/rfc7591)
