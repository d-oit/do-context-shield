import { Plugin } from "@opencode/plugin";
import type { SessionContext } from "@opencode/plugin/promise/session";

import { parseAdapterConfig, type AdapterConfig } from "./config.ts";
import { sanitizeContext } from "./context.ts";
import { AdapterError } from "./errors.ts";
import { McpClient } from "./mcp-client.ts";

const FAILURE = new AdapterError();

export default Plugin.define({
  id: "do-context-shield-egress",
  async setup(ctx) {
    let config: AdapterConfig | undefined;
    try {
      config = parseAdapterConfig(ctx.options);
    } catch {
      config = undefined;
    }

    let lifecycleHealthy = true;
    let clientPromise: Promise<McpClient> | undefined;
    const sessions = new Set<string>();
    const deletedSessions = new Set<string>();
    const abort = new AbortController();

    await ctx.session.hook("context", async (event: SessionContext) => {
      if (!lifecycleHealthy || !config || deletedSessions.has(event.sessionID)) {
        throw FAILURE;
      }
      clientPromise ??= McpClient.start(config.command);
      const client = await clientPromise;
      sessions.add(event.sessionID);
      await sanitizeContext(event, (text, sessionID) => client.sanitize(text, sessionID, config.context));
    });

    const watcher = (async () => {
      try {
        for await (const event of ctx.event.subscribe({ types: ["session.deleted"], signal: abort.signal })) {
          if (event.type !== "session.deleted") {
            continue;
          }
          const sessionID = event.data.sessionID;
          deletedSessions.add(sessionID);
          if (!sessions.delete(sessionID)) {
            continue;
          }
          try {
            const client = await clientPromise;
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
      abort.abort();
      await watcher;
      const client = await clientPromise?.catch(() => undefined);
      if (client) {
        for (const sessionID of sessions) {
          try {
            await client.forget(sessionID);
          } catch {
            break;
          }
        }
        await client.close();
      }
      sessions.clear();
      deletedSessions.clear();
    };
  },
});
