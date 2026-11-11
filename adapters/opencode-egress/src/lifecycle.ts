import type { Context } from "@opencode/plugin/promise/plugin";
import type { SessionContext } from "@opencode/plugin/promise/session";

import type { AdapterConfig } from "./config.ts";
import { AdapterError } from "./errors.ts";
import { sanitizeContext } from "./context.ts";
import type { McpClient } from "./mcp-client.ts";

const FAILURE = new AdapterError();

type LifecycleClient = Pick<McpClient, "sanitize" | "forget" | "close">;
type StartClient = (command: string) => Promise<LifecycleClient>;

export async function setupAdapterLifecycle(
  ctx: Context,
  config: AdapterConfig | undefined,
  startClient: StartClient,
): Promise<() => Promise<void>> {
  let lifecycleHealthy = true;
  let unloading = false;
  let clientPromise: Promise<LifecycleClient> | undefined;
  const sessions = new Set<string>();
  const deletedSessions = new Set<string>();
  const inFlight = new Map<string, Set<Promise<void>>>();
  const abort = new AbortController();

  function assertSessionAvailable(sessionID: string): void {
    if (!lifecycleHealthy || unloading || !config || deletedSessions.has(sessionID)) {
      throw FAILURE;
    }
  }

  function beginSession(sessionID: string): () => void {
    assertSessionAvailable(sessionID);
    const completion = Promise.withResolvers<void>();
    const active = inFlight.get(sessionID) ?? new Set<Promise<void>>();
    active.add(completion.promise);
    inFlight.set(sessionID, active);
    sessions.add(sessionID);
    let released = false;

    return () => {
      if (released) {
        return;
      }
      released = true;
      active.delete(completion.promise);
      completion.resolve();
      if (active.size === 0) {
        inFlight.delete(sessionID);
      }
    };
  }

  async function drainSession(sessionID: string): Promise<void> {
    const active = inFlight.get(sessionID);
    if (active) {
      await Promise.all([...active]);
    }
  }

  await ctx.session.hook("context", async (event: SessionContext) => {
    const release = beginSession(event.sessionID);
    try {
      const activeConfig = config;
      if (!activeConfig) {
        throw FAILURE;
      }
      clientPromise ??= startClient(activeConfig.command);
      const client = await clientPromise;
      assertSessionAvailable(event.sessionID);
      await sanitizeContext(event, async (text, sessionID) => {
        assertSessionAvailable(sessionID);
        const sanitized = await client.sanitize(text, sessionID, activeConfig.context);
        assertSessionAvailable(sessionID);
        return sanitized;
      });
      assertSessionAvailable(event.sessionID);
    } finally {
      release();
    }
  });

  const watcher = (async () => {
    try {
      for await (const event of ctx.event.subscribe({ types: ["session.deleted"], signal: abort.signal })) {
        if (event.type !== "session.deleted") {
          continue;
        }
        const sessionID = event.data.sessionID;
        deletedSessions.add(sessionID);
        const tracked = sessions.delete(sessionID);
        await drainSession(sessionID);
        if (!tracked) {
          continue;
        }
        try {
          const client = await clientPromise?.catch(() => undefined);
          if (client) {
            await client.forget(sessionID);
          }
        } catch {
          lifecycleHealthy = false;
          const client = await clientPromise?.catch(() => undefined);
          await client?.close();
          break;
        }
      }
    } catch {
      if (!abort.signal.aborted) {
        lifecycleHealthy = false;
      }
    } finally {
      if (!abort.signal.aborted) {
        lifecycleHealthy = false;
        const client = await clientPromise?.catch(() => undefined);
        await client?.close();
      }
    }
  })();

  return async () => {
    unloading = true;
    abort.abort();
    await watcher;
    const client = await clientPromise?.catch(() => undefined);
    for (const sessionID of sessions) {
      await drainSession(sessionID);
      if (client) {
        try {
          await client.forget(sessionID);
        } catch {
          break;
        }
      }
    }
    await client?.close();
    sessions.clear();
    deletedSessions.clear();
    inFlight.clear();
  };
}
