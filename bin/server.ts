import { isIP } from "node:net";
import { serve } from "@hono/node-server";
import { behindProxy } from "x-forwarded-fetch";
import { configureSentry } from "../src/sentry";

import app from "../src/index";

// biome-ignore lint/complexity/useLiteralKeys: tsc complains about this (TS4111)
configureSentry(process.env["SENTRY_DSN"]);

// biome-ignore lint/complexity/useLiteralKeys: tsc complains about this (TS4111)
const BEHIND_PROXY = process.env["BEHIND_PROXY"] === "true";

// biome-ignore lint/complexity/useLiteralKeys: tsc complains about this (TS4111)
const LISTEN_HOST = process.env["LISTEN_HOST"];

// biome-ignore lint/complexity/useLiteralKeys: tsc complains about this (TS4111)
const LISTEN_PORT = Number.parseInt(process.env["LISTEN_PORT"] ?? "3000", 10);

if (!Number.isInteger(LISTEN_PORT)) {
  console.error("Invalid LISTEN_PORT: must be an integer");
  process.exit(1);
}

if (LISTEN_HOST && LISTEN_HOST !== "localhost" && !isIP(LISTEN_HOST)) {
  console.error("Invalid LISTEN_HOST: must be an IP address, if specified");
  process.exit(1);
}

serve(
  {
    fetch: BEHIND_PROXY
      ? behindProxy(app.fetch.bind(app))
      : app.fetch.bind(app),
    port: LISTEN_PORT,
    hostname: LISTEN_HOST ?? "localhost",
  },
  (info) => {
    let host = info.address;
    if (LISTEN_HOST === "localhost") {
      host = "localhost";
    } else if (info.family === "IPv6") {
      host = `[${info.address}]`;
    }

    console.log(`Listening on http://${host}:${info.port}/`);
  },
);
