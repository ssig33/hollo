import { afterEach, beforeEach, describe, it } from "node:test";
import type { TestContext } from "node:test";

import { cleanDatabase } from "../../../tests/helpers";

import {
  bearerAuthorization,
  countApplications,
  createAccount,
  createOAuthApplication,
  getAccessToken,
  getApplication,
  getClientCredentialToken,
  getLastApplication,
} from "../../../tests/helpers/oauth";
import app from "../../index";
import { OOB_REDIRECT_URI } from "../../oauth/constants";
import type * as Schema from "../../schema";

describe("POST /api/v1/apps", () => {
  afterEach(async () => {
    await cleanDatabase();
  });

  it(
    "successfully creates a confidential client using FormData (by default)",
    { plan: 10 },
    async (t: TestContext) => {
      const body = new FormData();
      body.append("scopes", "read:accounts");

      const response = await app.request("/api/v1/apps", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const credentialApplication = await response.json();
      const application = await getLastApplication();

      t.assert.equal(typeof credentialApplication, "object");
      t.assert.equal(credentialApplication.id, application.id);
      t.assert.deepEqual(
        credentialApplication.redirect_uris,
        application.redirectUris,
      );
      t.assert.equal(
        credentialApplication.redirect_uri,
        application.redirectUris.join(" "),
      );

      t.assert.deepEqual(application.redirectUris, []);
      t.assert.deepEqual(application.scopes, ["read:accounts"]);
      t.assert.equal(application.confidential, true);
    },
  );

  it(
    "successfully creates a confidential client without duplicate scopes",
    { plan: 7 },
    async (t: TestContext) => {
      const body = new FormData();
      body.append("scopes", "read:accounts read:accounts");

      const response = await app.request("/api/v1/apps", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const credentialApplication = await response.json();
      const application = await getLastApplication();

      t.assert.equal(typeof credentialApplication, "object");
      t.assert.equal(credentialApplication.id, application.id);

      t.assert.deepEqual(application.scopes, ["read:accounts"]);
      t.assert.equal(application.confidential, true);
    },
  );

  it(
    "successfully creates a confidential client using JSON (by default)",
    { plan: 11 },
    async (t: TestContext) => {
      const body = JSON.stringify({ scopes: "read:accounts" });

      const response = await app.request("/api/v1/apps", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const credentialApplication = await response.json();
      const application = await getLastApplication();

      t.assert.equal(typeof credentialApplication, "object");
      t.assert.deepEqual(Object.keys(credentialApplication), [
        "id",
        "name",
        "website",
        "redirect_uris",
        "redirect_uri",
        "client_id",
        // Note: for public clients, this won't be present:
        "client_secret",
        "vapid_key",
      ]);
      t.assert.equal(credentialApplication.id, application.id);
      t.assert.deepEqual(
        credentialApplication.redirect_uris,
        application.redirectUris,
      );
      t.assert.equal(
        credentialApplication.redirect_uri,
        application.redirectUris.join(" "),
      );

      t.assert.deepEqual(application.redirectUris, []);
      t.assert.deepEqual(application.scopes, ["read:accounts"]);
      t.assert.equal(application.confidential, true);
    },
  );

  it(
    "successfully creates an application with read scope by default",
    { plan: 10 },
    async (t: TestContext) => {
      const body = new FormData();
      body.append("redirect_uris", OOB_REDIRECT_URI);

      const response = await app.request("/api/v1/apps", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const credentialApplication = await response.json();
      const application = await getLastApplication();

      t.assert.equal(typeof credentialApplication, "object");
      t.assert.equal(credentialApplication.id, application.id);
      t.assert.deepEqual(
        credentialApplication.redirect_uris,
        application.redirectUris,
      );
      t.assert.equal(
        credentialApplication.redirect_uri,
        application.redirectUris.join(" "),
      );

      t.assert.deepEqual(application.redirectUris, [OOB_REDIRECT_URI]);
      t.assert.deepEqual(application.scopes, ["read"]);
      t.assert.equal(application.confidential, true);
    },
  );

  // TODO: Support public clients
  it.skip("successfully creates a public client application");

  // Validation
  it(
    "prevents creating an application with invalid scopes",
    { plan: 6 },
    async (t: TestContext) => {
      const prevAppCount = await countApplications();
      const body = new FormData();
      body.append("scopes", "invalid read:accounts");

      const response = await app.request("/api/v1/apps", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 422);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const error = await response.json();
      const appCount = await countApplications();

      t.assert.equal(typeof error, "object");
      t.assert.equal(error.error, "invalid_request");

      t.assert.equal(
        appCount,
        prevAppCount,
        "Should not change the number of applications registered",
      );
    },
  );

  it(
    "prevents creating an application with invalid redirect_uris",
    { plan: 6 },
    async (t: TestContext) => {
      const prevAppCount = await countApplications();
      const body = new FormData();
      body.append("redirect_uris", "invalid");

      const response = await app.request("/api/v1/apps", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 422);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const error = await response.json();
      const appCount = await countApplications();

      t.assert.equal(typeof error, "object");
      t.assert.equal(error.error, "invalid_request");

      t.assert.equal(
        appCount,
        prevAppCount,
        "Should not change the number of applications registered",
      );
    },
  );

  it(
    "prevents creating an application if any of the redirect_uris are invalid",
    { plan: 6 },
    async (t: TestContext) => {
      const prevAppCount = await countApplications();
      const body = JSON.stringify({
        redirect_uris: [OOB_REDIRECT_URI, "invalid"],
      });

      const response = await app.request("/api/v1/apps", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body,
      });

      t.assert.equal(response.status, 422);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const error = await response.json();
      const appCount = await countApplications();

      t.assert.equal(typeof error, "object");
      t.assert.equal(error.error, "invalid_request");

      t.assert.equal(
        appCount,
        prevAppCount,
        "Should not change the number of applications registered",
      );
    },
  );

  it(
    "prevents creating an application with invalid parameters",
    { plan: 6 },
    async (t: TestContext) => {
      const prevAppCount = await countApplications();
      const body = new FormData();
      body.append("invalid_property", "invalid");

      const response = await app.request("/api/v1/apps", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 422);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const error = await response.json();
      const appCount = await countApplications();

      t.assert.equal(typeof error, "object");
      t.assert.equal(error.error, "invalid_request");

      t.assert.equal(
        appCount,
        prevAppCount,
        "Should not change the number of applications registered",
      );
    },
  );
});

/**
 * Theoretically, you should be able to verify application credentials for the
 * Client Authentication (client_id, client_secret) without needing an access
 * token, but currently the Mastodon API requires an access token.
 */
describe("GET /api/v1/apps/verify_credentials", () => {
  let client: Awaited<ReturnType<typeof createOAuthApplication>>;
  let application: Schema.Application;
  let account: Awaited<ReturnType<typeof createAccount>>;

  beforeEach(async () => {
    account = await createAccount();
    client = await createOAuthApplication({
      scopes: ["read:accounts"],
      confidential: true,
    });
    application = await getApplication(client);
  });

  afterEach(async () => {
    await cleanDatabase();
  });

  async function actsLikeAnApplicationResponse(
    t: TestContext,
    response: Response,
  ) {
    t.assert.equal(response.status, 200);
    t.assert.equal(response.headers.get("content-type"), "application/json");
    t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

    const applicationEntity = await response.json();

    t.assert.equal(typeof applicationEntity, "object");
    t.assert.deepEqual(Object.keys(applicationEntity), [
      "id",
      "name",
      "website",
      "scopes",
      "redirect_uris",
      "redirect_uri",
    ]);

    t.assert.equal(applicationEntity.id, application.id);
    t.assert.equal(applicationEntity.name, application.name);
    t.assert.equal(applicationEntity.website, application.website);
    t.assert.ok(Array.isArray(applicationEntity.scopes));
    t.assert.ok(Array.isArray(applicationEntity.redirect_uris));
    t.assert.deepEqual(applicationEntity.scopes, application.scopes);
    t.assert.deepEqual(
      applicationEntity.redirect_uris,
      application.redirectUris,
    );
    t.assert.equal(typeof applicationEntity.redirect_uri, "string");
  }

  it(
    "successfully returns an application using client credentials",
    { plan: 13 },
    async (t: TestContext) => {
      const clientCredential = await getClientCredentialToken(client);
      const response = await app.request("/api/v1/apps/verify_credentials", {
        method: "GET",
        headers: {
          authorization: bearerAuthorization(clientCredential),
        },
      });

      await actsLikeAnApplicationResponse(t, response);
    },
  );

  it(
    "successfully returns an application using an access token",
    { plan: 13 },
    async (t: TestContext) => {
      const accessToken = await getAccessToken(client, account);
      const response = await app.request("/api/v1/apps/verify_credentials", {
        method: "GET",
        headers: {
          authorization: bearerAuthorization(accessToken),
        },
      });

      await actsLikeAnApplicationResponse(t, response);
    },
  );
});
