import { z } from "zod";

export const DiscoverResultSchema = z.object({ supportedVersions: z.array(z.string()) }).passthrough();
export const ToolsListResultSchema = z.object({
  resultType: z.literal("complete"),
  tools: z.array(z.object({ name: z.string() }).passthrough()),
}).passthrough();
export const TextContentSchema = z.object({ type: z.literal("text"), text: z.string() }).passthrough();
export const ToolCallResultSchema = z.object({
  resultType: z.literal("complete"),
  isError: z.boolean().optional(),
  content: z.array(TextContentSchema),
}).passthrough();
export const ForgottenResultSchema = z.object({ session: z.string(), forgotten: z.literal(true) }).passthrough();
export const JsonRpcResponseSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.number().int().positive(),
  result: z.unknown(),
  error: z.never().optional(),
}).passthrough();
