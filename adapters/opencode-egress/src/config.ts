import { z } from "zod";

import { failClosed } from "./errors.ts";

const AdapterOptionsSchema = z.object({
  command: z.string().min(1).max(4096).refine((value) => !value.includes("\0")).optional(),
  recipient: z.enum(["local", "trusted", "external", "unknown"]).optional(),
  dataCategory: z.enum(["non_personal", "personal", "special_category"]).optional(),
  purpose: z.string().max(4096).optional(),
  jurisdiction: z.string().regex(/^[A-Za-z]{2}$/).optional(),
}).strict();

export type Recipient = "local" | "trusted" | "external" | "unknown";
export type DataCategory = "non_personal" | "personal" | "special_category";

export interface ProcessingContext {
  readonly recipient: Recipient;
  readonly dataCategory: DataCategory;
  readonly purpose?: string;
  readonly jurisdiction?: string;
}

export interface AdapterConfig {
  readonly command: string;
  readonly context: ProcessingContext;
}

export function parseAdapterConfig(value: unknown): AdapterConfig {
  let options: z.infer<typeof AdapterOptionsSchema>;
  try {
    options = AdapterOptionsSchema.parse(value ?? {});
  } catch {
    failClosed();
  }

  const context: ProcessingContext = {
    recipient: options.recipient ?? "external",
    dataCategory: options.dataCategory ?? "personal",
    ...(options.purpose === undefined ? {} : { purpose: options.purpose }),
    ...(options.jurisdiction === undefined ? {} : { jurisdiction: options.jurisdiction }),
  };
  return { command: options.command ?? "do-context-shield", context };
}
