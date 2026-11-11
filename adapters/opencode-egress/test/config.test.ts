import { test } from "bun:test";

import { parseAdapterConfig } from "../src/config.ts";

const GENERIC_ERROR = "unable to sanitize outbound context";

function assertRejected(value: unknown): void {
  try {
    parseAdapterConfig(value);
  } catch (error) {
    if (error instanceof Error && error.message === GENERIC_ERROR) {
      return;
    }
    throw new Error("invalid adapter configuration did not fail generically");
  }
  throw new Error("invalid adapter configuration unexpectedly passed");
}

test("uses conservative egress context defaults and accepts explicit processing context", () => {
  const defaults = parseAdapterConfig(undefined);
  if (defaults.command !== "do-context-shield" || defaults.context.recipient !== "external" || defaults.context.dataCategory !== "personal") {
    throw new Error("adapter defaults are not conservative");
  }

  const configured = parseAdapterConfig({
    command: "/opt/bin/do-context-shield",
    recipient: "trusted",
    dataCategory: "special_category",
    purpose: "source review",
    jurisdiction: "GB",
  });
  if (
    configured.command !== "/opt/bin/do-context-shield" ||
    configured.context.recipient !== "trusted" ||
    configured.context.dataCategory !== "special_category" ||
    configured.context.purpose !== "source review" ||
    configured.context.jurisdiction !== "GB"
  ) {
    throw new Error("explicit processing context was not retained");
  }
});

test("rejects unknown settings and malformed enforcement context", () => {
  assertRejected({ recipient: "trusted", dataCategory: "personal", allowFallback: true });
  assertRejected({ recipient: "unrecognized", dataCategory: "personal" });
  assertRejected({ recipient: "external", dataCategory: "personal", jurisdiction: "USA" });
  assertRejected({ command: "", recipient: "external", dataCategory: "personal" });
});
