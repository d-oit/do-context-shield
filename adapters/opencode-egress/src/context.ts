import { Buffer } from "node:buffer";
import { z } from "zod";
import type { SessionContext } from "@opencode/plugin/promise/session";

import { AdapterError, failClosed } from "./errors.ts";
import { isRecord, type JsonRecord } from "./guards.ts";

export const MAX_CONTEXT_BYTES = 1_048_576;
const MAX_UNIQUE_STRINGS = 512;
const MAX_DEPTH = 64;
const MAX_SANITIZE_MS = 30_000;
type TreeShape = "generic" | "messages" | "message" | "parts" | "part" | "tool-result-value";

const TextPartSchema = z.object({ type: z.literal("text"), text: z.string() }).passthrough();
const EffortPartSchema = z.object({ type: z.literal("effort") }).passthrough();
const ReasoningPartSchema = z.object({ type: z.literal("reasoning"), text: z.string() }).passthrough();
const ToolCallPartSchema = z.object({
  type: z.literal("tool-call"),
  id: z.string(),
  name: z.string(),
  input: z.unknown(),
}).passthrough();
const ToolResultValueSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("json"), value: z.unknown() }).passthrough(),
  z.object({ type: z.literal("text"), value: z.unknown() }).passthrough(),
  z.object({ type: z.literal("error"), value: z.unknown() }).passthrough(),
  z.object({ type: z.literal("content"), value: z.array(TextPartSchema) }).passthrough(),
]);
const ToolResultPartSchema = z.object({
  type: z.literal("tool-result"),
  id: z.string(),
  name: z.string(),
  result: ToolResultValueSchema,
}).passthrough();
const CompactionPartSchema = z.object({
  type: z.literal("compaction"),
  text: z.union([z.string(), z.null()]).optional(),
  encrypted: z.never().optional(),
}).passthrough();
const SystemMessagePartSchema = z.discriminatedUnion("type", [TextPartSchema, EffortPartSchema]);
const AssistantMessagePartSchema = z.discriminatedUnion("type", [
  TextPartSchema,
  ReasoningPartSchema,
  ToolCallPartSchema,
  ToolResultPartSchema,
  CompactionPartSchema,
  EffortPartSchema,
]);
const UserMessageSchema = z.object({ role: z.literal("user"), content: z.array(TextPartSchema) }).passthrough();
const SystemMessageSchema = z.object({ role: z.literal("system"), content: z.array(SystemMessagePartSchema) }).passthrough();
const AssistantMessageSchema = z.object({ role: z.literal("assistant"), content: z.array(AssistantMessagePartSchema) }).passthrough();
const ToolMessageSchema = z.object({ role: z.literal("tool"), content: z.array(ToolResultPartSchema) }).passthrough();
const ModelMessageSchema = z.discriminatedUnion("role", [
  SystemMessageSchema,
  UserMessageSchema,
  AssistantMessageSchema,
  ToolMessageSchema,
]);
const OutboundContextSchema = z.object({
  sessionID: z.string().min(1).max(256).refine((value) => !/[\u0000-\u001f\u007f]/.test(value)),
  system: z.array(TextPartSchema),
  messages: z.array(ModelMessageSchema),
  tools: z.record(z.string(), z.object({ description: z.string(), input: z.record(z.string(), z.unknown()) }).passthrough()),
  options: z.record(z.string(), z.unknown()),
}).passthrough();

type OutboundContext = z.infer<typeof OutboundContextSchema>;
type Budget = { bytes: number; readonly strings: Set<string> };
export type TextSanitizer = (text: string, sessionID: string) => Promise<string>;

function requireRecord(value: unknown): JsonRecord {
  if (!isRecord(value)) {
    failClosed();
  }
  return value;
}

function accountString(value: string, budget: Budget): void {
  budget.bytes += Buffer.byteLength(value, "utf8");
  if (budget.bytes > MAX_CONTEXT_BYTES) {
    failClosed();
  }
  budget.strings.add(value);
  if (budget.strings.size > MAX_UNIQUE_STRINGS) {
    failClosed();
  }
}

function validateJson(value: unknown, budget: Budget, depth: number, ancestors: WeakSet<object>): void {
  if (depth > MAX_DEPTH) {
    failClosed();
  }
  if (typeof value === "string") {
    accountString(value, budget);
    return;
  }
  if (value === null || value === undefined || typeof value === "boolean") {
    return;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      failClosed();
    }
    return;
  }
  if (typeof value !== "object") {
    failClosed();
  }
  if (ancestors.has(value)) {
    failClosed();
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      for (const item of value) {
        validateJson(item, budget, depth + 1, ancestors);
      }
      return;
    }
    if (!isRecord(value) || "toJSON" in value || Object.getOwnPropertySymbols(value).length > 0) {
      failClosed();
    }
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (!descriptor.enumerable || !("value" in descriptor)) {
        failClosed();
      }
      accountString(key, budget);
      validateJson(descriptor.value, budget, depth + 1, ancestors);
    }
  } finally {
    ancestors.delete(value);
  }
}

function preflight(event: SessionContext): OutboundContext {
  const parsed = OutboundContextSchema.safeParse(event);
  if (!parsed.success || Buffer.byteLength(parsed.data.sessionID, "utf8") > 256) {
    failClosed();
  }
  const context = parsed.data;
  const budget: Budget = { bytes: 0, strings: new Set() };
  const ancestors = new WeakSet<object>();
  validateJson(context.system, budget, 0, ancestors);
  validateJson(context.messages, budget, 0, ancestors);
  validateJson(context.tools, budget, 0, ancestors);
  validateJson(context.options, budget, 0, ancestors);
  return context;
}

function timed<T>(operation: Promise<T>, deadline: number): Promise<T> {
  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    return Promise.reject(new AdapterError());
  }
  const { promise, resolve, reject } = Promise.withResolvers<T>();
  const timer = setTimeout(() => reject(new AdapterError()), remaining);
  operation.then(resolve, reject);
  return promise.finally(() => clearTimeout(timer));
}

async function sanitizeTree(
  value: unknown,
  sessionID: string,
  sanitizer: TextSanitizer,
  cache: Map<string, string>,
  deadline: number,
  depth: number,
  shape: TreeShape = "generic",
  structural = false,
): Promise<unknown> {
  if (depth > MAX_DEPTH) {
    failClosed();
  }
  if (typeof value === "string") {
    let sanitized: string;
    if (cache.has(value)) {
      sanitized = cache.get(value) as string;
    } else {
      sanitized = await timed(sanitizer(value, sessionID), deadline);
      if (typeof sanitized !== "string") {
        failClosed();
      }
      cache.set(value, sanitized);
    }
    if (structural && sanitized !== value) {
      failClosed();
    }
    return sanitized;
  }
  if (value === null || value === undefined || typeof value === "boolean" || typeof value === "number") {
    return value;
  }
  if (Array.isArray(value)) {
    const output: unknown[] = [];
    const itemShape = shape === "messages" ? "message" : shape === "parts" ? "part" : "generic";
    for (const item of value) {
      output.push(await sanitizeTree(item, sessionID, sanitizer, cache, deadline, depth + 1, itemShape));
    }
    return output;
  }
  const source = requireRecord(value);
  const output: JsonRecord = {};
  const partType = source.type;
  const toolPart = shape === "part" && (partType === "tool-call" || partType === "tool-result");
  for (const [key, item] of Object.entries(source)) {
    const sanitizedKey = await sanitizeTree(key, sessionID, sanitizer, cache, deadline, depth + 1, "generic", true);
    if (typeof sanitizedKey !== "string" || sanitizedKey !== key) {
      failClosed();
    }
    const structuralValue =
      (shape === "message" && key === "role") ||
      ((shape === "part" || shape === "tool-result-value") && key === "type") ||
      (toolPart && (key === "id" || key === "name"));
    let childShape: TreeShape = "generic";
    if (shape === "message" && key === "content") {
      childShape = "parts";
    } else if (shape === "part" && partType === "tool-result" && key === "result") {
      childShape = "tool-result-value";
    } else if (shape === "tool-result-value" && partType === "content" && key === "value") {
      childShape = "parts";
    }
    Object.defineProperty(output, key, {
      configurable: true,
      enumerable: true,
      value: await sanitizeTree(item, sessionID, sanitizer, cache, deadline, depth + 1, childShape, structuralValue),
      writable: true,
    });
  }
  return output;
}

export async function sanitizeContext(event: SessionContext, sanitizer: TextSanitizer): Promise<void> {
  try {
    const context = preflight(event);
    const deadline = Date.now() + MAX_SANITIZE_MS;
    const cache = new Map<string, string>();
    const system = await sanitizeTree(context.system, context.sessionID, sanitizer, cache, deadline, 0, "parts");
    const messages = await sanitizeTree(context.messages, context.sessionID, sanitizer, cache, deadline, 0, "messages");
    const tools = await sanitizeTree(context.tools, context.sessionID, sanitizer, cache, deadline, 0);
    const options = await sanitizeTree(context.options, context.sessionID, sanitizer, cache, deadline, 0);
    event.system = system as SessionContext["system"];
    event.messages = messages as SessionContext["messages"];
    event.tools = tools as SessionContext["tools"];
    event.options = options as SessionContext["options"];
  } catch {
    failClosed();
  }
}
