import { strict as assert } from "node:assert";
import { test } from "bun:test";
import type { SessionContext } from "@opencode/plugin/promise/session";

import { MAX_CONTEXT_BYTES, sanitizeContext } from "../src/context.ts";

const CANARY = "egress-probe@example.invalid";
const REDACTED = "__DO_PRIVATE_EMAIL_1__";
const GENERIC_ERROR = "unable to sanitize outbound context";

function context(): SessionContext {
  return {
    sessionID: "ses_adapter_test",
    model: { providerID: "openai", id: "fake-model" },
    agent: "build",
    system: [{ type: "text", text: `System note: ${CANARY}`, metadata: { source: CANARY } }],
    messages: [
      { role: "user", content: [{ type: "text", text: `Request ${CANARY}` }] },
      {
        role: "assistant",
        content: [{ type: "tool-call", id: "call-1", name: "read_file", input: { path: CANARY } }],
      },
      {
        role: "tool",
        content: [{ type: "tool-result", id: "call-1", name: "read_file", result: { type: "text", value: CANARY } }],
      },
    ],
    tools: {
      read_file: {
        description: `Read ${CANARY}`,
        input: { type: "object", properties: { path: { type: "string", description: CANARY } } },
      },
    },
    options: { temperature: 0.2, name: CANARY, providerOption: { note: CANARY } },
  } as unknown as SessionContext;
}

function assertCanaryAbsent(value: unknown): void {
  if (JSON.stringify(value).includes(CANARY)) {
    throw new Error("raw canary reached model-facing context");
  }
}

test("sanitizes system, conversation, tool schema, and request options in one session scope", async () => {
  const event = context();
  const scopes = new Set<string>();

  await sanitizeContext(event, async (text, sessionID) => {
    scopes.add(sessionID);
    return text.replaceAll(CANARY, REDACTED);
  });

  assertCanaryAbsent({ system: event.system, messages: event.messages, tools: event.tools, options: event.options });
  assert.equal(scopes.size, 1);
  assert.equal(scopes.has("ses_adapter_test"), true);
  assert.equal(event.messages[0]?.content[0]?.type, "text");
  assert.equal(event.messages[0]?.content[0]?.text, `Request ${REDACTED}`);
  assert.equal(event.tools.read_file?.description, `Read ${REDACTED}`);
  assert.equal((event.options as Record<string, unknown>).name, REDACTED);
});

test("rejects attachments and unknown message parts before sanitization", async () => {
  for (const type of ["media", "future-content-part"]) {
    const event = context();
    event.messages = [
      { role: "user", content: [{ type, text: CANARY }] },
    ] as unknown as SessionContext["messages"];
    let calls = 0;

    try {
      await sanitizeContext(event, async (text) => {
        calls += 1;
        return text;
      });
      throw new Error("unsupported context unexpectedly passed");
    } catch (error) {
      if (!(error instanceof Error) || error.message !== GENERIC_ERROR) {
        throw new Error("unsupported context did not fail with a generic diagnostic");
      }
    }

    assert.equal(calls, 0);
  }
});

test("rejects oversized context before calling the sanitizer", async () => {
  const event = context();
  event.system = [{ type: "text", text: "x".repeat(MAX_CONTEXT_BYTES + 1) }];
  let calls = 0;

  try {
    await sanitizeContext(event, async (text) => {
      calls += 1;
      return text;
    });
    throw new Error("oversized context unexpectedly passed");
  } catch (error) {
    if (!(error instanceof Error) || error.message !== GENERIC_ERROR) {
      throw new Error("oversized context did not fail with a generic diagnostic");
    }
  }

  assert.equal(calls, 0);
});

test("does not partially mutate context when the sanitizer fails", async () => {
  const event = context();
  let calls = 0;
  const before = JSON.stringify({ system: event.system, messages: event.messages, tools: event.tools, options: event.options });

  try {
    await sanitizeContext(event, async () => {
      calls += 1;
      throw new Error(`child failure for ${CANARY}`);
    });
    throw new Error("sanitizer failure unexpectedly passed");
  } catch (error) {
    if (!(error instanceof Error) || error.message !== GENERIC_ERROR || error.message.includes(CANARY)) {
      throw new Error("sanitizer failure leaked input through diagnostics");
    }
  }

  const after = JSON.stringify({ system: event.system, messages: event.messages, tools: event.tools, options: event.options });
  assert.equal(after, before);
  assert.ok(calls > 0);
});

test("rejects a sensitive object key rather than forwarding or renaming it", async () => {
  const event = context();
  event.messages = [
    { role: "user", content: [{ type: "text", text: "safe" }] },
  ] as unknown as SessionContext["messages"];
  event.tools = {
    [CANARY]: { description: "tool", input: { type: "object" } },
  } as unknown as SessionContext["tools"];

  try {
    await sanitizeContext(event, async (text) => text.replaceAll(CANARY, REDACTED));
    throw new Error("sensitive object key unexpectedly passed");
  } catch (error) {
    if (!(error instanceof Error) || error.message !== GENERIC_ERROR) {
      throw new Error("sensitive object key did not fail closed");
    }
  }

  assert.equal(event.tools[CANARY] !== undefined, true);
});
