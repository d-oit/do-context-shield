import { Plugin } from "@opencode/plugin";

import { parseAdapterConfig, type AdapterConfig } from "./config.ts";
import { setupAdapterLifecycle } from "./lifecycle.ts";
import { McpClient } from "./mcp-client.ts";

export default Plugin.define({
  id: "do-context-shield-egress",
  async setup(ctx) {
    let config: AdapterConfig | undefined;
    try {
      config = parseAdapterConfig(ctx.options);
    } catch {
      config = undefined;
    }
    return setupAdapterLifecycle(ctx, config, (command) => McpClient.start(command));
  },
});
