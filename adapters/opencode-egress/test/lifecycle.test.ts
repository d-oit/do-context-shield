import { strict as assert } from "node:assert";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setDefaultTimeout, test } from "bun:test";
import type { Context } from "@opencode/plugin/promise/plugin";
import type { SessionContext } from "@opencode/plugin/promise/session";

import plugin from "../src/index.ts";
import { GENERIC_FAILURE } from "../src/errors.ts";

setDefaultTimeout(30_000);

const CANARY = "egress-probe@example.com";
const SESSION_A = "ses_adapter_deleted";
const SESSION_B = "ses_adapter_active";
const REDACTION = /__DO_PRIVATE_EMAIL_\d+_[0-9A-Fa-f]+__/;

type SessionHook = (event: SessionContext) => Promise<void>;

function sanitizerBinary(): string {
  const root = fileURLToPath(new URL("../../../", import.meta.url));
  const command = process.env.DO_CONTEXT_SHIELD_BIN ?? join(root, "target", "debug", "do-context-shield");
  if (!existsSync(command)) {
    throw new Error("build do-context-shield before running the adapter lifecycle test");
  }
  return command;
}

function context(sessionID: string): SessionContext {
  return {
    sessionID,
    model: { providerID: "openai", id: "fake-model" },
    agent: "build",
    system: [{ type: "text", text: `System ${CANARY}` }],
    messages: [{ role: "user", content: [{ type: "text", text: `Request ${CANARY}` }] }],
    tools: {},
    options: {},
  } as unknown as SessionContext;
}

function tokenFrom(event: SessionContext): string {
  const modelContext = JSON.stringify({ system: event.system, messages: event.messages });
  if (modelContext.includes(CANARY)) {
    throw new Error("OpenCode lifecycle hook left the raw canary in model context");
  }
  const token = modelContext.match(REDACTION)?.[0];
  if (!token) {
    throw new Error("OpenCode lifecycle hook omitted the pseudonym token");
  }
  return token;
}

test("session deletion forgets one scope while unload forgets the remaining scope", async () => {
  const deleteRequested = Promise.withResolvers<void>();
  const eventProcessed = Promise.withResolvers<void>();
  let sessionHook: SessionHook | undefined;
  let cleanup: (() => Promise<void> | void) | undefined;

  const fakeContext = {
    options: { command: sanitizerBinary() },
    session: {
      hook: async (name: string, handler: SessionHook) => {
        if (name !== "context") {
          throw new Error("adapter registered an unexpected OpenCode hook");
        }
        sessionHook = handler;
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
          yield { type: "session.deleted", data: { sessionID: SESSION_A } };
          eventProcessed.resolve();
          await aborted.promise;
        } finally {
          signal.removeEventListener("abort", onAbort);
        }
      })(),
    },
  } as unknown as Context;

  try {
    const registeredCleanup = await plugin.setup(fakeContext);
    const registeredHook = sessionHook;
    if (typeof registeredCleanup !== "function" || !registeredHook) {
      throw new Error("adapter did not register its hook and cleanup");
    }
    cleanup = registeredCleanup;

    const firstA = context(SESSION_A);
    await registeredHook(firstA);
    const tokenA = tokenFrom(firstA);
    const repeatedA = context(SESSION_A);
    await registeredHook(repeatedA);
    assert.equal(tokenFrom(repeatedA), tokenA, "one session must reuse its stable mapping");

    const firstB = context(SESSION_B);
    await registeredHook(firstB);
    assert.notEqual(tokenFrom(firstB), tokenA, "different sessions must not share mappings");

    deleteRequested.resolve();
    await eventProcessed.promise;
    await assert.rejects(() => registeredHook(context(SESSION_A)), (error: unknown) =>
      error instanceof Error && error.message === GENERIC_FAILURE,
    );

    const stillActive = context(SESSION_B);
    await registeredHook(stillActive);
    assert.equal(tokenFrom(stillActive), tokenFrom(firstB));

  } finally {
    deleteRequested.resolve();
    await cleanup?.();
  }
});
