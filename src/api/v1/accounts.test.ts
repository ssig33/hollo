import { afterEach, beforeEach, describe, it } from "node:test";
import type { TestContext } from "node:test";

import { cleanDatabase } from "../../../tests/helpers";
import {
  bearerAuthorization,
  createAccount,
  createOAuthApplication,
  getAccessToken,
} from "../../../tests/helpers/oauth";

import app from "../../index";

describe("/api/v1/accounts/", () => {
  let client: Awaited<ReturnType<typeof createOAuthApplication>>;
  let account: Awaited<ReturnType<typeof createAccount>>;

  beforeEach(async () => {
    account = await createAccount();
    client = await createOAuthApplication({
      scopes: ["read:accounts", "write"],
    });
  });

  afterEach(async () => {
    await cleanDatabase();
  });

  describe("verify_credentials", () => {
    it("Successfully returns the current accounts profile with a valid access token", async (t: TestContext) => {
      t.plan(7);

      const accessToken = await getAccessToken(client, account, [
        "read:accounts",
      ]);

      const response = await app.request(
        "/api/v1/accounts/verify_credentials",
        {
          method: "GET",
          headers: {
            authorization: bearerAuthorization(accessToken),
          },
        },
      );

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const credentialAccount = await response.json();

      t.assert.equal(typeof credentialAccount, "object");
      t.assert.equal(credentialAccount.id, account.id);
      t.assert.equal(credentialAccount.username, "hollo");
      t.assert.equal(credentialAccount.acct, "hollo@hollo.test");
    });

    it("does not return the account when an invalid scope is used", async (t: TestContext) => {
      t.plan(4);

      const accessToken = await getAccessToken(client, account, ["write"]);

      const response = await app.request(
        "/api/v1/accounts/verify_credentials",
        {
          method: "GET",
          headers: {
            authorization: bearerAuthorization(accessToken),
          },
        },
      );

      t.assert.equal(response.status, 403);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const error = await response.json();

      t.assert.deepStrictEqual(error, {
        error: "insufficient_scope",
      });
    });

    it("does not return the account when no access token is used", async (t: TestContext) => {
      t.plan(4);

      const response = await app.request(
        "/api/v1/accounts/verify_credentials",
        {
          method: "GET",
        },
      );

      t.assert.equal(response.status, 401);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const error = await response.json();

      t.assert.deepStrictEqual(error, {
        error: "unauthorized",
      });
    });
  });
});
