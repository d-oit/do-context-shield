import { Buffer } from "node:buffer";
import { spawn, type ChildProcess } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { z } from "zod";

import type { ProcessingContext } from "./config.ts";
import { AdapterError, failClosed } from "./errors.ts";
import {
  DiscoverResultSchema,
  ForgottenResultSchema,
  JsonRpcResponseSchema,
  ToolCallResultSchema,
  ToolsListResultSchema,
} from "./mcp-schemas.ts";

const MAX_FRAME_BYTES = 4 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 10_000;
const CLOSE_TIMEOUT_MS = 1_000;
const CLIENT_META = {
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientCapabilities": {},
  "io.modelcontextprotocol/clientInfo": {
    name: "do-context-shield-opencode-egress",
    version: "0.1.0",
  },
};
const CLI_ARGS = [
  "mcp-stdio",
  "--tools",
  "sanitize,forget",
  "--detector",
  "regex",
  "--policy",
  "default",
  "--transformer",
  "pseudonymize",
  "--vault",
  "memory",
];
const REQUIRED_TOOLS = ["context.forget", "context.sanitize"];
const SessionIDSchema = z.string().min(1).max(256).refine(
  (value) => Buffer.byteLength(value, "utf8") <= 256 && !/[\u0000-\u001f\u007f]/.test(value),
);

function childEnvironment(): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (value !== undefined && !name.startsWith("DO_CONTEXT_SHIELD_")) {
      environment[name] = value;
    }
  }
  return environment;
}

function withTimeout<T>(operation: Promise<T>, milliseconds: number): Promise<T> {
  const { promise, resolve, reject } = Promise.withResolvers<T>();
  const timer = setTimeout(() => reject(new AdapterError()), milliseconds);
  operation.then(resolve, reject);
  return promise.finally(() => clearTimeout(timer));
}

function parseResult<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    failClosed();
  }
  return parsed.data;
}

export class McpClient {
  private readonly child: ChildProcess;
  private readonly lines: Interface;
  private readonly lineIterator: AsyncIterator<string>;
  private readonly exit: Promise<void>;
  private queue: Promise<void> = Promise.resolve();
  private nextID = 1;
  private closed = false;
  private closePromise: Promise<void> | undefined;

  private constructor(child: ChildProcess, lines: Interface) {
    this.child = child;
    this.lines = lines;
    this.lineIterator = lines[Symbol.asyncIterator]();
    const { promise, resolve } = Promise.withResolvers<void>();
    this.exit = promise;
    child.once("close", () => resolve());
    child.once("error", () => resolve());
    child.stderr?.on("data", () => undefined);
  }

  static async start(command: string): Promise<McpClient> {
    let child: ChildProcess;
    try {
      child = spawn(command, CLI_ARGS, {
        env: childEnvironment(),
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
    } catch {
      throw new AdapterError();
    }
    if (!child.stdin || !child.stdout || !child.stderr) {
      child.kill();
      throw new AdapterError();
    }

    const client = new McpClient(child, createInterface({ input: child.stdout, crlfDelay: Infinity }));
    try {
      const discovery = parseResult(DiscoverResultSchema, await client.request("server/discover", {}));
      if (!discovery.supportedVersions.includes("2026-07-28")) {
        failClosed();
      }
      const listed = parseResult(ToolsListResultSchema, await client.request("tools/list", {}));
      const names = listed.tools.map((tool) => tool.name).sort();
      if (names.length !== REQUIRED_TOOLS.length || names.some((name, index) => name !== REQUIRED_TOOLS[index])) {
        failClosed();
      }
      return client;
    } catch {
      await client.close();
      throw new AdapterError();
    }
  }

  async sanitize(text: string, sessionID: string, context: ProcessingContext): Promise<string> {
    if (!SessionIDSchema.safeParse(sessionID).success) {
      throw new AdapterError();
    }
    const result = parseResult(ToolCallResultSchema, await this.request("tools/call", {
      name: "context.sanitize",
      arguments: {
        text,
        session: sessionID,
        recipient: context.recipient,
        data_category: context.dataCategory,
        ...(context.purpose === undefined ? {} : { purpose: context.purpose }),
        ...(context.jurisdiction === undefined ? {} : { jurisdiction: context.jurisdiction }),
      },
    }));
    if (result.isError === true || result.content.length !== 1) {
      throw new AdapterError();
    }
    return result.content[0]!.text;
  }

  async forget(sessionID: string): Promise<void> {
    if (!SessionIDSchema.safeParse(sessionID).success) {
      throw new AdapterError();
    }
    const result = parseResult(ToolCallResultSchema, await this.request("tools/call", {
      name: "context.forget",
      arguments: { session: sessionID },
    }));
    if (result.isError === true || result.content.length !== 1) {
      throw new AdapterError();
    }
    let response: unknown;
    try {
      response = JSON.parse(result.content[0]!.text) as unknown;
    } catch {
      throw new AdapterError();
    }
    const details = parseResult(ForgottenResultSchema, response);
    if (details.session !== sessionID) {
      throw new AdapterError();
    }
  }

  async close(): Promise<void> {
    this.closePromise ??= this.finishClose();
    return this.closePromise;
  }

  private request(method: string, params: Record<string, unknown>): Promise<unknown> {
    const response = this.queue.then(() => this.exchange(method, params));
    this.queue = response.then(() => undefined, () => undefined);
    return response;
  }

  private async exchange(method: string, params: Record<string, unknown>): Promise<unknown> {
    if (this.closed || !this.child.stdin) {
      throw new AdapterError();
    }
    const id = this.nextID;
    this.nextID += 1;
    const frame = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method,
      params: { ...params, _meta: CLIENT_META },
    });
    if (Buffer.byteLength(frame, "utf8") > MAX_FRAME_BYTES) {
      throw new AdapterError();
    }

    try {
      const { promise, resolve, reject } = Promise.withResolvers<void>();
      this.child.stdin.write(`${frame}\n`, (error) => (error ? reject(error) : resolve()));
      await withTimeout(promise, REQUEST_TIMEOUT_MS);
      const next = await withTimeout(this.lineIterator.next(), REQUEST_TIMEOUT_MS);
      if (next.done || Buffer.byteLength(next.value, "utf8") > MAX_FRAME_BYTES) {
        failClosed();
      }
      const parsed = parseResult(JsonRpcResponseSchema, JSON.parse(next.value) as unknown);
      if (parsed.id !== id) {
        failClosed();
      }
      return parsed.result;
    } catch {
      this.abort();
      throw new AdapterError();
    }
  }

  private abort(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.lines.close();
    this.child.kill();
  }

  private async finishClose(): Promise<void> {
    this.closed = true;
    this.lines.close();
    this.child.stdin?.end();
    try {
      await withTimeout(this.exit, CLOSE_TIMEOUT_MS);
      return;
    } catch {
      this.child.kill();
    }
    try {
      await withTimeout(this.exit, CLOSE_TIMEOUT_MS);
    } catch {
      this.child.kill("SIGKILL");
    }
  }
}
