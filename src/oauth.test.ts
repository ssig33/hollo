import { describe, test } from "node:test";
import type { TestContext } from "node:test";

import app from "./index";

describe("OAuth", async () => {
  await test("GET /.well-known/oauth-authorization-server", async (t: TestContext) => {
    t.plan(10);

    const response = await app.request(
      "http://localhost:3000/.well-known/oauth-authorization-server",
      {
        method: "get",
      },
    );

    t.assert.equal(response.status, 200, "Should return 200-ok");

    const metadata = await response.json();

    t.assert.equal(metadata.issuer, "http://localhost:3000/");
    t.assert.equal(
      metadata.authorization_endpoint,
      "http://localhost:3000/oauth/authorize",
    );
    t.assert.equal(
      metadata.token_endpoint,
      "http://localhost:3000/oauth/token",
    );
    // Non-standard, mastodon extension:
    t.assert.equal(
      metadata.app_registration_endpoint,
      "http://localhost:3000/api/v1/apps",
    );

    t.assert.deepStrictEqual(metadata.response_types_supported, ["code"]);
    t.assert.deepStrictEqual(metadata.response_modes_supported, ["query"]);
    t.assert.deepStrictEqual(metadata.grant_types_supported, [
      "authorization_code",
      "client_credentials",
    ]);
    t.assert.deepStrictEqual(metadata.token_endpoint_auth_methods_supported, [
      "client_secret_post",
    ]);

    t.assert.ok(
      Array.isArray(metadata.scopes_supported),
      "Should return an array of scopes supported",
    );
  });
});
