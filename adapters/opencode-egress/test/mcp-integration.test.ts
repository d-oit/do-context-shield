import { strict as assert } from "node:assert";
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import { Buffer } from "node:buffer";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { setDefaultTimeout, test } from "bun:test";
import type { SessionContext } from "@opencode/plugin/promise/session";

import { parseAdapterConfig } from "../src/config.ts";
import { sanitizeContext } from "../src/context.ts";
import { GENERIC_FAILURE } from "../src/errors.ts";
import { McpClient } from "../src/mcp-client.ts";

setDefaultTimeout(30_000);

const CANARY = "egress-probe@example.com";
const REDACTION = /__DO_PRIVATE_EMAIL_\d+_[0-9A-Fa-f]+__/;
const SESSION_ID = "ses_adapter_integration";

type ProviderObservation = { containsCanary: boolean; containsRedaction: boolean };

function integrationContext(): SessionContext {
  return {
    sessionID: SESSION_ID,
    model: { providerID: "openai", id: "fake-model" },
    agent: "build",
    system: [{ type: "text", text: `System ${CANARY}` }],
    messages: [{ role: "user", content: [{ type: "text", text: `Please inspect ${CANARY}` }] }],
    tools: {
      read_file: {
        description: `Read ${CANARY}`,
        input: { type: "object", properties: { path: { type: "string" } } },
      },
    },
    options: { temperature: 0.2 },
  } as unknown as SessionContext;
}

async function startFakeProvider(observations: ProviderObservation[]): Promise<{ server: Server; url: string }> {
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk: Buffer | string) => {
      body += chunk.toString();
    });
    request.on("end", () => {
      observations.push({ containsCanary: body.includes(CANARY), containsRedaction: REDACTION.test(body) });
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{\"ok\":true}");
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("fake provider failed to bind a loopback port");
  }
  return { server, url: `http://127.0.0.1:${address.port}/v1/chat/completions` };
}

function sanitizerBinary(): string {
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  const command = process.env.DO_CONTEXT_SHIELD_BIN ?? join(root, "target", "debug", "do-context-shield");
  if (!existsSync(command)) {
    throw new Error("build do-context-shield before running the adapter integration test");
  }
  return command;
}

async function postToFakeProvider(url: string, event: SessionContext): Promise<void> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ system: event.system, messages: event.messages, tools: event.tools, options: event.options }),
  });
  if (!response.ok) {
    throw new Error("fake provider rejected the sanitized request");
  }
}

test("sanitizes the real CLI context before a fake provider receives it and forgets the session", async () => {
  const observations: ProviderObservation[] = [];
  const provider = await startFakeProvider(observations);
  const client = await McpClient.start(sanitizerBinary());
  const context = parseAdapterConfig(undefined).context;
  const event = integrationContext();

  try {
    const first = await client.sanitize(CANARY, SESSION_ID, context);
    const repeated = await client.sanitize(CANARY, SESSION_ID, context);
    if (first !== repeated || first.includes(CANARY) || !REDACTION.test(first)) {
      throw new Error("session-scoped sanitizer did not produce a stable email redaction");
    }
    await sanitizeContext(event, (text, sessionID) => client.sanitize(text, sessionID, context));
    await postToFakeProvider(provider.url, event);

    if (observations.length !== 1 || observations[0]?.containsCanary || !observations[0]?.containsRedaction) {
      throw new Error("fake provider observed an unsanitized or incomplete context");
    }
    await client.forget(SESSION_ID);
  } finally {
    await client.close();
    provider.server.close();
    await once(provider.server, "close");
  }
});

test("does not inherit ambient jurisdiction that can weaken an explicit adapter context", async () => {
  const previousJurisdiction = process.env.DO_CONTEXT_SHIELD_JURISDICTION;
  process.env.DO_CONTEXT_SHIELD_JURISDICTION = "US";
  let client: McpClient | undefined;

  try {
    const activeClient = await McpClient.start(sanitizerBinary());
    client = activeClient;
    await assert.rejects(
      () => activeClient.sanitize(CANARY, "ses_ambient_jurisdiction", {
        recipient: "trusted",
        dataCategory: "special_category",
      }),
      (error: unknown) => error instanceof Error && error.message === GENERIC_FAILURE,
    );
  } finally {
    if (previousJurisdiction === undefined) {
      delete process.env.DO_CONTEXT_SHIELD_JURISDICTION;
    } else {
      process.env.DO_CONTEXT_SHIELD_JURISDICTION = previousJurisdiction;
    }
    await client?.close();
  }
});

test("a sanitizer failure stops the fake provider call and exposes no raw diagnostics", async () => {
  const observations: ProviderObservation[] = [];
  const provider = await startFakeProvider(observations);
  const event = integrationContext();

  try {
    try {
      await sanitizeContext(event, async () => {
        throw new Error(`synthetic failure ${CANARY}`);
      });
      await postToFakeProvider(provider.url, event);
      throw new Error("sanitizer failure unexpectedly reached the model boundary");
    } catch (error) {
      if (!(error instanceof Error) || error.message !== GENERIC_FAILURE || error.message.includes(CANARY)) {
        throw new Error("sanitizer diagnostic was not generic");
      }
    }
    assert.equal(observations.length, 0);
  } finally {
    provider.server.close();
    await once(provider.server, "close");
  }
});
