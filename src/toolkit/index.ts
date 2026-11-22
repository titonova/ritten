import type { ZodType } from 'zod';
export interface ToolContext {
  signal: AbortSignal;
  log(message: string): Promise<void>;
  call(tool: string, args: unknown): Promise<unknown>;
}
export interface ToolDefinition {
  description: string;
  inputSchema: ZodType;
  readOnly?: boolean;
  run(input: unknown, context: ToolContext): Promise<unknown>;
}
/** Custom tools are trusted local code; the context does not sandbox direct Node APIs. */
export function defineTool<T extends ZodType>(
  tool: Omit<ToolDefinition, 'inputSchema' | 'run'> & {
    inputSchema: T;
    run(input: T['_output'], context: ToolContext): Promise<unknown>;
  },
): ToolDefinition {
  return tool as ToolDefinition;
}
