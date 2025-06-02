import { Hono } from "hono";
import * as Schema from "../../schema";

const app = new Hono();

app.get("/", (c) => {
  const url = new URL(c.req.url);

  return c.json({
    issuer: new URL("/", url).href,
    authorization_endpoint: new URL("/oauth/authorize", url).href,
    token_endpoint: new URL("/oauth/token", url).href,
    revocation_endpoint: new URL("/oauth/revoke", url).href,
    userinfo_endpoint: new URL("/oauth/userinfo", url).href,
    scopes_supported: Schema.scopeEnum.enumValues,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "client_credentials"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
      // Not supported until we support public clients:
      // "none",
    ],
    code_challenge_methods_supported: ["S256"],
    app_registration_endpoint: new URL("/api/v1/apps", url).href,
  });
});

export default app;
