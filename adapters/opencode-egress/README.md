# OpenCode V2 egress adapter

`do-context-shield-opencode-egress` is a private, optional OpenCode V2 server plugin. It sanitizes the supported OpenCode agent context before dispatch through the `context` hook, using the existing `do-context-shield mcp-stdio` pipeline. It is not a provider proxy or a general network-egress control.

## Setup

Build the local sanitizer binary and install the plugin's pinned JavaScript dependencies:

```sh
cargo build -p do-context-shield
cd adapters/opencode-egress
bun install --frozen-lockfile
```

Register the package directory in `opencode.json` or `opencode.jsonc`:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "/absolute/path/do-context-shield/adapters/opencode-egress",
      "options": {
        "command": "/absolute/path/do-context-shield/target/debug/do-context-shield",
        "recipient": "external",
        "dataCategory": "personal"
      }
    }
  ]
}
```

`command` is the path to the executable only; the plugin supplies `mcp-stdio` and its fail-closed sanitizer settings. It defaults to `do-context-shield` on `PATH`. `recipient` defaults to `external`; `dataCategory` defaults to `personal`. Optional `purpose` and two-letter `jurisdiction` are forwarded as the same enforcement context accepted by `context.sanitize`. Unknown options and malformed values make outbound context processing fail closed. The child removes inherited `DO_CONTEXT_SHIELD_*` environment variables so ambient jurisdiction or policy settings cannot override adapter options.

OpenCode's current plugin guide supports local package directories in `plugins`; V1 plugins do not run under the V2 plugin API. See [OpenCode plugin loading](https://opencode.ai/docs/build/plugins/) and the [V2 server plugin API](https://opencode.ai/docs/build/plugins/server/).

## Boundary and lifecycle

- Uses the OpenCode `sessionID` as the explicit vault scope, so repeated values stay stable within one session and do not share mappings across sessions.
- Uses the memory vault in its local MCP child. Mappings stay on the machine and are forgotten on session deletion/unload; they are lost if the child exits.
- Sanitizes supported text in system context, messages, tool definitions, tool calls/results, and options before assigning the sanitized event fields. Sanitizer and validation errors throw from the hook before model dispatch.
- Starts the local MCP server with only `context.sanitize` and `context.forget`; it never exposes `context.restore` to the model.
- Calls `context.forget` on `session.deleted` and for active sessions during plugin unload. Failure of the lifecycle watcher or a forget call blocks later context processing.
- Fails closed on malformed/unknown context shapes, media or file attachments, oversized context, sanitizer errors/timeouts, invalid configuration, or an unavailable/misbehaving MCP child. Errors are generic and do not include submitted text.

## Limits

This plugin registers only OpenCode's `context` hook. It is not a network filter and does not cover other OpenCode hooks such as title or compaction generation, direct provider/API calls, other clients, shell/subprocess traffic, or network requests made by unrelated plugins. Disabling or bypassing the plugin bypasses this boundary.

The adapter uses the built-in regex detector, default policy, and pseudonymizing transformer. Regex detection is not exhaustive, so this is not complete data-loss prevention. Treat it as an optional OpenCode agent-context adapter, not universal egress enforcement.

## Check

From the repository root, `bash scripts/check-opencode-egress.sh` builds the real CLI, typechecks the plugin, runs unit tests, and exercises the MCP sanitizer against a loopback-only fake provider. The integration test checks that the fake provider receives a pseudonymized context, that a sanitizer failure sends no provider request, and that session mappings can be forgotten.
