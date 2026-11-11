import { strict as assert } from "node:assert";
import { setDefaultTimeout, test } from "bun:test";
import type { Context } from "@opencode/plugin/promise/plugin";
import type { SessionContext } from "@opencode/plugin/promise/session";

import { parseAdapterConfig } from "../src/config.ts";
import { GENERIC_FAILURE } from "../src/errors.ts";
import { setupAdapterLifecycle } from "../src/lifecycle.ts";

setDefaultTimeout(30_000);

const CANARY = "lifecycle-race@example.com";
const SESSION = "ses_lifecycle_race";
const SYSTEM_TEXT = `System ${CANARY}`;

type SessionHook = (event: SessionContext) => Promise<void>;
type TestClient = {
  sanitize(text: string, sessionID: string): Promise<string>;
  forget(sessionID: string): Promise<void>;
  close(): Promise<void>;
};

function context(): SessionContext {
  return {
    sessionID: SESSION,
    model: { providerID: "openai", id: "fake-model" },
    agent: "build",
    system: [{ type: "text", text: SYSTEM_TEXT }],
    messages: [{ role: "user", content: [{ type: "text", text: `Request ${CANARY}` }] }],
    tools: {},
    options: {},
  } as unknown as SessionContext;
}

async function flushEventTurn(): Promise<void> {
  await new Promise<void>((resolve) => setImmediate(resolve));
}

async function resolvesBeforeNextTurn(promise: Promise<void>): Promise<boolean> {
  return Promise.race([
    promise.then(() => true),
    new Promise<boolean>((resolve) => setImmediate(() => resolve(false))),
  ]);
}

async function makeHarness(startClient: (command: string) => Promise<TestClient>) {
  const deleteRequested = Promise.withResolvers<void>();
  let registeredHook: SessionHook | undefined;
  let cleanup: (() => Promise<void> | void) | undefined;
  const fakeContext = {
    options: { command: "unused-test-command" },
    session: {
      hook: async (name: string, handler: SessionHook) => {
        assert.equal(name, "context");
        registeredHook = handler;
      },
    },
    event: {
      subscribe: ({ signal }: { signal: AbortSignal }) => (async function* () {
        const aborted = Promise.withResolvers<void>();
        const onAbort = () => aborted.resolve();
        if (signal.aborted) {
          return;
        }
        signal.addEventListener("abort", onAbort, { once: true });
        try {
          await Promise.race([deleteRequested.promise, aborted.promise]);
          if (signal.aborted) {
            return;
          }
          yield { type: "session.deleted", data: { sessionID: SESSION } };
          await aborted.promise;
        } finally {
          signal.removeEventListener("abort", onAbort);
        }
      })(),
    },
  } as unknown as Context;

  cleanup = await setupAdapterLifecycle(fakeContext, parseAdapterConfig({ command: "unused-test-command" }), startClient);
  if (!registeredHook || !cleanup) {
    throw new Error("lifecycle test harness did not register the context hook and cleanup");
  }
  return {
    hook: (event: SessionContext) => registeredHook!(event),
    delete: () => deleteRequested.resolve(),
    cleanup,
  };
}

function isGenericFailure(error: unknown): boolean {
  return error instanceof Error && error.message === GENERIC_FAILURE;
}

test("deletion during MCP startup blocks later work and forgets after the hook drains", async () => {
  const startup = Promise.withResolvers<TestClient>();
  const startRequested = Promise.withResolvers<void>();
  const forgotten = Promise.withResolvers<void>();
  let startupResolved = false;
  let sanitizerCalls = 0;
  const client: TestClient = {
    sanitize: async (text) => {
      sanitizerCalls += 1;
      return text;
    },
    forget: async () => {
      assert.equal(startupResolved, true, "forget must wait for the startup-blocked hook");
      forgotten.resolve();
    },
    close: async () => {},
  };
  const harness = await makeHarness(async () => {
    startRequested.resolve();
    return startup.promise;
  });

  try {
    const firstHook = harness.hook(context()).then(() => false, isGenericFailure);
    await startRequested.promise;
    harness.delete();
    await flushEventTurn();

    const laterHook = Promise.race([
      harness.hook(context()).then(() => false, isGenericFailure),
      new Promise<boolean>((resolve) => setImmediate(() => resolve(false))),
    ]);

    startupResolved = true;
    startup.resolve(client);
    const [firstFailedClosed, laterFailedClosed] = await Promise.all([firstHook, laterHook]);
    const wasForgotten = await resolvesBeforeNextTurn(forgotten.promise);
    assert.equal(wasForgotten, true, "deletion must forget after in-flight startup settles");
    assert.equal(firstFailedClosed, true);
    assert.equal(laterFailedClosed, true, "a deleted session must reject new hooks immediately");
    assert.equal(sanitizerCalls, 0, "startup completion must not start sanitization after deletion");
  } finally {
    startupResolved = true;
    startup.resolve(client);
    harness.delete();
    await harness.cleanup();
  }
});

test("deletion during an MCP sanitize call prevents later calls and forgets after it drains", async () => {
  const sanitizeResponse = Promise.withResolvers<string>();
  const sanitizeStarted = Promise.withResolvers<void>();
  const forgotten = Promise.withResolvers<void>();
  let sanitizerCalls = 0;
  let sanitizeSettled = false;
  const client: TestClient = {
    sanitize: async (text) => {
      sanitizerCalls += 1;
      if (text === SYSTEM_TEXT) {
        sanitizeStarted.resolve();
        try {
          return await sanitizeResponse.promise;
        } finally {
          sanitizeSettled = true;
        }
      }
      return text;
    },
    forget: async () => {
      assert.equal(sanitizeSettled, true, "forget must wait for the in-flight sanitize response");
      forgotten.resolve();
    },
    close: async () => {},
  };
  const harness = await makeHarness(async () => client);

  try {
    const event = context();
    const original = JSON.stringify(event);
    const hookResult = harness.hook(event).then(() => false, isGenericFailure);
    await sanitizeStarted.promise;
    const callsAtDeletion = sanitizerCalls;

    harness.delete();
    await flushEventTurn();
    const laterHook = Promise.race([
      harness.hook(context()).then(() => false, isGenericFailure),
      new Promise<boolean>((resolve) => setImmediate(() => resolve(false))),
    ]);

    sanitizeResponse.resolve("sanitized system text");
    const [hookFailedClosed, laterFailedClosed] = await Promise.all([hookResult, laterHook]);
    const wasForgotten = await resolvesBeforeNextTurn(forgotten.promise);
    assert.equal(wasForgotten, true, "deletion must forget after the sanitize call settles");
    assert.equal(hookFailedClosed, true);
    assert.equal(laterFailedClosed, true, "a deleted session must reject new hooks immediately");
    assert.equal(sanitizerCalls, callsAtDeletion, "no MCP sanitize call may start after deletion");
    assert.equal(JSON.stringify(event), original, "a cancelled context must remain unmodified");
  } finally {
    sanitizeResponse.resolve("sanitized system text");
    harness.delete();
    await harness.cleanup();
  }
});
