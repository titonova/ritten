# Custom and external tools

Toolsets are trusted local executable code. They are not isolated from Node.js or the OS. Review code and pin its dependencies before enabling it. New files never enable themselves.

## Custom toolsets

Set `toolsets.directories` to local directories containing named folders. The OS-default toolset directory is also scanned. `RITTEN_TOOLSET_PATHS` prepends directories using the platform path delimiter. The first matching folder wins; built-in names are reserved. Names use letters, digits, underscores, and hyphens; entries beginning with `_` are helpers, not tools.

For example, `notes/search.ts` exposes `notes.search`; `notes/create/index.js` exposes `notes.create`. Symlinks are rejected. Only names in `toolsets.enabled` are imported. Restart after changing code or enablement.

```typescript
import { z } from 'zod';
import { defineTool } from 'ritten-mcp/toolkit';

export default defineTool({
  description: 'Return a greeting',
  inputSchema: z.strictObject({ name: z.string().min(1).max(100) }),
  readOnly: true,
  async run(input, context) {
    context.signal.throwIfAborted();
    await context.log('Greeting requested');
    return { greeting: `Hello ${input.name}` };
  },
});
```

The pinned `tsx` runtime handles TypeScript imports. A toolset may have its own dependencies. Use a compatible Zod instance and an object input schema. Package-level toolkit exports support ESM. Fingerprints include toolset source/helper files and metadata, excluding `node_modules` and dotfiles; code dependencies must be pinned and reviewed separately. Toolsets are limited to 500 fingerprinted entries and 5MB of source/metadata. Optional `toolset.yaml` metadata is validated; scope declarations and suggested policies remain descriptive and never grant permissions.

`context.call(name,args)` invokes another granted tool through the same pipeline, including its separate policy/approval/scope checks. For example, delegate file reads to `filesystem.read_file` rather than calling Node directly. `context.log(message)` writes redacted audit events; `context.signal` provides cancellation. These are the complete helper interfaces currently available. Manifest policy suggestions are never applied automatically.

Enable the folder locally in configuration, add explicit policy rules, and grant a credential tools such as `notes.search`. Tool hints do not authorize execution. Custom tools default to mutation handling unless `readOnly` is explicitly true; this hint never bypasses policy.

## External stdio MCP servers

External servers are enabled explicitly in `external_servers`:

```yaml
external_servers:
  - name: image-tools
    command: C:/Python/python.exe
    args: [-m, image_tools_mcp]
    working_directory: C:/Tools/image-tools
    environment:
      PYTHONUTF8: '1'
    enabled: true
    startup_timeout: 10s
    call_timeout: 30s
```

Executable and working-directory paths must be absolute. Only explicitly configured environment values are inherited; default SDK inherited values are cleared. Configure any necessary PATH/SystemRoot values deliberately. Stdio messages are bounded at 1MB. Stderr is drained without reflecting it to clients. Startup failure closes already-started servers and fails Ritten startup.

Tools appear as `image-tools.TOOLNAME`, pass schema conversion/validation, and use the common credentials, policy, approvals, audit, and result limits. External server names must be unique and cannot replace built-ins. A custom tool with the same final name causes startup failure. Tool metadata is fingerprinted. Remote clients cannot register external processes.

Ritten cancels external requests and closes transports at shutdown. External executable code is trusted: it can create its own processes or side effects outside the helper interfaces. No sandbox guarantees are implied.
