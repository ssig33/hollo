import { afterEach, beforeEach, describe, it } from "node:test";
import type { TestContext } from "node:test";

import app from "./index";
import type * as Schema from "./schema";

import { cleanDatabase } from "../tests/helpers";
import {
  basicAuthorization,
  createAccount,
  createOAuthApplication,
  findAccessGrant,
  findAccessToken,
  getAccessToken,
  getApplication,
  getLastAccessGrant,
  getLastAccessToken,
  revokeAccessGrant,
} from "../tests/helpers/oauth";
import { getLoginCookie } from "../tests/helpers/web";
import { OOB_REDIRECT_URI } from "./oauth/constants";
import { createAccessGrant } from "./oauth/helpers";

describe("OAuth", () => {
  it(
    "Can GET /.well-known/oauth-authorization-server",
    { plan: 10 },
    async (t: TestContext) => {
      // We use the full URL in this test as the route calculates values based
      // on the Host header
      const response = await app.request(
        "http://localhost:3000/.well-known/oauth-authorization-server",
        {
          method: "GET",
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
        "client_secret_basic",
      ]);

      t.assert.ok(
        Array.isArray(metadata.scopes_supported),
        "Should return an array of scopes supported",
      );
    },
  );
});

describe("OAuth / POST /oauth/authorize", () => {
  let application: Schema.Application;
  let client: Awaited<ReturnType<typeof createOAuthApplication>>;
  let account: Awaited<ReturnType<typeof createAccount>>;
  const APP_REDIRECT_URI = "custom://oauth_callback";

  beforeEach(async () => {
    account = await createAccount();
    client = await createOAuthApplication({
      scopes: ["read:accounts"],
      redirectUris: [OOB_REDIRECT_URI, APP_REDIRECT_URI],
      confidential: true,
    });
    application = await getApplication(client);
  });

  afterEach(async () => {
    await cleanDatabase();
  });

  it(
    "Does not create an access grant if denied",
    { plan: 2 },
    async (t: TestContext) => {
      const cookie = await getLoginCookie();
      const formData = new FormData();

      formData.set("account_id", account.id);
      formData.set("application_id", application.id);
      formData.set("redirect_uri", APP_REDIRECT_URI);
      formData.set("scopes", "read:accounts");
      formData.set("decision", "deny");

      const response = await app.request("/oauth/authorize", {
        method: "POST",
        body: formData,
        headers: {
          Cookie: cookie,
        },
      });

      t.assert.equal(response.status, 302);
      t.assert.equal(
        response.headers.get("Location"),
        "custom://oauth_callback?error=access_denied&error_description=The+resource+owner+or+authorization+server+denied+the+request.",
      );
    },
  );

  it(
    "Can return authorization code out-of-bounds",
    { plan: 8 },
    async (t: TestContext) => {
      const cookie = await getLoginCookie();
      const formData = new FormData();

      formData.set("account_id", account.id);
      formData.set("application_id", application.id);
      formData.set("redirect_uri", OOB_REDIRECT_URI);
      formData.set("scopes", "read:accounts");
      formData.set("decision", "allow");

      const response = await app.request("/oauth/authorize", {
        method: "POST",
        body: formData,
        headers: {
          Cookie: cookie,
        },
      });

      t.assert.equal(response.status, 200);
      t.assert.match(response.headers.get("content-type") ?? "", /text\/html/);

      const responseBody = await response.text();
      const lastAccessGrant = await getLastAccessGrant();

      t.assert.equal(lastAccessGrant.applicationId, application.id);
      t.assert.equal(lastAccessGrant.resourceOwnerId, account.id);
      t.assert.equal(lastAccessGrant.redirectUri, OOB_REDIRECT_URI);
      t.assert.deepStrictEqual(lastAccessGrant.scopes, ["read:accounts"]);
      t.assert.strictEqual(lastAccessGrant.revoked, null);

      t.assert.match(
        responseBody,
        new RegExp(`${lastAccessGrant.code}`),
        "Response should contain the access grant code",
      );
    },
  );

  it(
    "Can return authorization code via redirect",
    { plan: 7 },
    async (t: TestContext) => {
      const cookie = await getLoginCookie();
      const formData = new FormData();

      formData.set("account_id", account.id);
      formData.set("application_id", application.id);
      formData.set("redirect_uri", APP_REDIRECT_URI);
      formData.set("scopes", "read:accounts");
      formData.set("state", "test_state_value");
      formData.set("decision", "allow");

      const response = await app.request("/oauth/authorize", {
        method: "POST",
        body: formData,
        headers: {
          Cookie: cookie,
        },
      });

      t.assert.equal(response.status, 302);

      const lastAccessGrant = await getLastAccessGrant();
      t.assert.equal(lastAccessGrant.applicationId, application.id);
      t.assert.equal(lastAccessGrant.resourceOwnerId, account.id);
      t.assert.equal(lastAccessGrant.redirectUri, APP_REDIRECT_URI);
      t.assert.deepStrictEqual(lastAccessGrant.scopes, ["read:accounts"]);
      t.assert.strictEqual(lastAccessGrant.revoked, null);

      t.assert.equal(
        response.headers.get("Location"),
        `${APP_REDIRECT_URI}?code=${lastAccessGrant.code}&state=test_state_value`,
      );
    },
  );
});

describe("OAuth / POST /oauth/token (Confidential Client)", () => {
  let account: Awaited<ReturnType<typeof createAccount>>;
  let application: Schema.Application;
  let client: Awaited<ReturnType<typeof createOAuthApplication>>;
  let wrongApplication: Schema.Application;
  let wrongClient: Awaited<ReturnType<typeof createOAuthApplication>>;

  beforeEach(async () => {
    account = await createAccount();
    client = await createOAuthApplication({
      scopes: ["read:accounts"],
      redirectUris: [OOB_REDIRECT_URI],
      confidential: true,
    });
    application = await getApplication(client);

    wrongClient = await createOAuthApplication({
      scopes: ["write:accounts"],
      redirectUris: [OOB_REDIRECT_URI],
      confidential: true,
    });
    wrongApplication = await getApplication(wrongClient);
  });

  afterEach(async () => {
    await cleanDatabase();
  });

  it(
    "cannot request an access token without using a client authentication method",
    { plan: 3 },
    async (t: TestContext) => {
      // Here we are deliberately not using any client authentication method,
      // which is not acceptable

      const body = new FormData();
      body.set("grant_type", "client_credentials");
      body.set("scope", "read:accounts");

      const response = await app.request("/oauth/token", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 401);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();
      t.assert.equal(responseBody.error, "invalid_client");
    },
  );

  it(
    "cannot request an access token using multiple client authentication methods",
    { plan: 3 },
    async (t: TestContext) => {
      // Here we are using both client_secret_post and client_secret_basic
      // together, which is not acceptable

      const body = new FormData();
      body.set("grant_type", "client_credentials");
      body.set("client_id", application.clientId);
      body.set("client_secret", application.clientSecret);
      body.set("scope", "read:accounts");

      const response = await app.request("/oauth/token", {
        method: "POST",
        headers: {
          authorization: basicAuthorization(application),
        },
        body,
      });

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();
      t.assert.equal(responseBody.error, "invalid_request");
    },
  );

  it(
    "cannot request an access token using invalid client authentication",
    { plan: 3 },
    async (t: TestContext) => {
      const body = new FormData();
      body.set("grant_type", "client_credentials");
      body.set("client_id", application.clientId);
      body.set("client_secret", "invalid");
      body.set("scope", "read:accounts");

      const response = await app.request("/oauth/token", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 401);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();
      t.assert.equal(responseBody.error, "invalid_client");
    },
  );

  // Client Credentials Grant Flow
  it(
    "can request an access token using the client credentials grant flow with client_secret_basic",
    { plan: 7 },
    async (t: TestContext) => {
      const body = new FormData();
      body.set("grant_type", "client_credentials");
      body.set("scope", "read:accounts");

      const response = await app.request("/oauth/token", {
        method: "POST",
        headers: {
          authorization: basicAuthorization(application),
        },
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();
      const lastAccessToken = await getLastAccessToken();

      t.assert.equal(lastAccessToken.grant_type, "client_credentials");
      t.assert.deepStrictEqual(lastAccessToken.scopes, ["read:accounts"]);
      t.assert.equal(
        responseBody.access_token,
        lastAccessToken.code,
        "Generates an Access Token",
      );
      t.assert.equal(responseBody.token_type, "Bearer");
      t.assert.equal(responseBody.scope, lastAccessToken.scopes.join(" "));
    },
  );

  it(
    "can request an access token using the client credentials grant flow with client_secret_post",
    { plan: 7 },
    async (t: TestContext) => {
      const body = new FormData();
      body.set("grant_type", "client_credentials");
      body.set("client_id", application.clientId);
      body.set("client_secret", application.clientSecret);
      body.set("scope", "read:accounts");

      const response = await app.request("/oauth/token", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();
      const lastAccessToken = await getLastAccessToken();

      t.assert.equal(lastAccessToken.grant_type, "client_credentials");
      t.assert.deepStrictEqual(lastAccessToken.scopes, ["read:accounts"]);
      t.assert.equal(
        responseBody.access_token,
        lastAccessToken.code,
        "Generates an Access Token",
      );
      t.assert.equal(responseBody.token_type, "Bearer");
      t.assert.equal(responseBody.scope, lastAccessToken.scopes.join(" "));
    },
  );

  it(
    "can request an access token using the client credentials grant flow using JSON body",
    { plan: 7 },
    async (t: TestContext) => {
      const body = JSON.stringify({
        grant_type: "client_credentials",
        client_id: application.clientId,
        client_secret: application.clientSecret,
        scope: "read:accounts",
      });

      const response = await app.request("/oauth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const lastAccessToken = await getLastAccessToken();
      const responseBody = await response.json();

      t.assert.equal(lastAccessToken.grant_type, "client_credentials");
      t.assert.deepStrictEqual(lastAccessToken.scopes, ["read:accounts"]);
      t.assert.equal(
        responseBody.access_token,
        lastAccessToken.code,
        "Generates an Access Token",
      );
      t.assert.equal(responseBody.token_type, "Bearer");
      t.assert.equal(responseBody.scope, lastAccessToken.scopes.join(" "));
    },
  );

  it(
    "cannot request client credentials grant flow with scope not registered to the application",
    { plan: 4 },
    async (t: TestContext) => {
      const body = new FormData();
      body.set("grant_type", "client_credentials");
      body.set("scope", "write:accounts");

      const response = await app.request("/oauth/token", {
        method: "POST",
        headers: {
          authorization: basicAuthorization(application),
        },
        body,
      });

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const responseBody = await response.json();
      t.assert.equal(responseBody.error, "invalid_scope");
    },
  );

  // OAuth Authorization Code Grant Flow
  it(
    "can exchange an access grant for an access token",
    { plan: 8 },
    async (t: TestContext) => {
      const accessGrant = await createAccessGrant(
        application.id,
        account.id,
        ["read:accounts"],
        OOB_REDIRECT_URI,
      );

      const body = new FormData();
      body.set("grant_type", "authorization_code");
      body.set("client_id", application.clientId);
      // client_secret is technically optional, but we don't support public clients yet:
      body.set("client_secret", application.clientSecret);
      body.set("redirect_uri", OOB_REDIRECT_URI);
      body.set("code", accessGrant.code);

      const response = await app.request("/oauth/token", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();

      const lastAccessToken = await getLastAccessToken();
      const changedAccessGrant = await findAccessGrant(accessGrant.code);

      t.assert.notEqual(
        changedAccessGrant.revoked,
        null,
        "Successfully revokes the access grant",
      );
      t.assert.equal(lastAccessToken.grant_type, "authorization_code");
      t.assert.deepStrictEqual(
        lastAccessToken.scopes,
        changedAccessGrant.scopes,
      );

      t.assert.equal(
        responseBody.access_token,
        lastAccessToken.code,
        "Generates an Access Token",
      );
      t.assert.equal(responseBody.token_type, "Bearer");
      t.assert.equal(responseBody.scope, lastAccessToken.scopes.join(" "));
    },
  );

  // This test case needs time travel, lines 332-339
  it.skip(
    "cannot exchange an access grant for an access token when the access grant has expired",
  );

  it(
    "cannot exchange an access grant for an access token when the redirect URI does not match",
    { plan: 3 },
    async (t: TestContext) => {
      const accessGrant = await createAccessGrant(
        application.id,
        account.id,
        ["read:accounts"],
        OOB_REDIRECT_URI,
      );

      const body = new FormData();
      body.set("grant_type", "authorization_code");
      body.set("client_id", application.clientId);
      // client_secret is technically optional, but we don't support public clients yet:
      body.set("client_secret", application.clientSecret);
      body.set("redirect_uri", "https://invalid.example/");
      body.set("code", accessGrant.code);

      const response = await app.request("/oauth/token", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();

      t.assert.equal(responseBody.error, "invalid_grant");
    },
  );

  it(
    "cannot exchange an access grant for an access token when the client does not match",
    { plan: 3 },
    async (t: TestContext) => {
      const accessGrant = await createAccessGrant(
        application.id,
        account.id,
        ["read:accounts"],
        OOB_REDIRECT_URI,
      );

      const body = new FormData();
      body.set("grant_type", "authorization_code");
      body.set("client_id", wrongApplication.clientId);
      // client_secret is technically optional, but we don't support public clients yet:
      body.set("client_secret", wrongApplication.clientSecret);
      body.set("redirect_uri", OOB_REDIRECT_URI);
      body.set("code", accessGrant.code);

      const response = await app.request("/oauth/token", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();

      t.assert.equal(responseBody.error, "invalid_grant");
    },
  );

  it(
    "cannot exchange an access grant for an access token when the access grant is revoked",
    { plan: 3 },
    async (t: TestContext) => {
      const accessGrant = await createAccessGrant(
        application.id,
        account.id,
        ["read:accounts"],
        OOB_REDIRECT_URI,
      );

      await revokeAccessGrant(accessGrant);

      const body = new FormData();
      body.set("grant_type", "authorization_code");
      body.set("client_id", application.clientId);
      // client_secret is technically optional, but we don't support public clients yet:
      body.set("client_secret", application.clientSecret);
      body.set("redirect_uri", OOB_REDIRECT_URI);
      body.set("code", accessGrant.code);

      const response = await app.request("/oauth/token", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();

      t.assert.equal(responseBody.error, "invalid_grant");
    },
  );

  // Unsupported authorization grant flow:
  it(
    "cannot use an unsupported grant_type",
    { plan: 4 },
    async (t: TestContext) => {
      const body = new FormData();
      body.set("grant_type", "invalid");

      const response = await app.request("/oauth/token", {
        method: "POST",
        headers: {
          authorization: basicAuthorization(application),
        },
        body,
      });

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const responseBody = await response.json();

      t.assert.equal(typeof responseBody, "object");
      t.assert.equal(responseBody.error, "unsupported_grant_type");
    },
  );

  // Invalid request
  it("cannot use unknown parameters", { plan: 4 }, async (t: TestContext) => {
    const body = new FormData();
    body.set("grant_type", "client_credentials");
    body.set("redirect_uri", OOB_REDIRECT_URI);

    const response = await app.request("/oauth/token", {
      method: "POST",
      headers: {
        authorization: basicAuthorization(application),
      },
      body,
    });

    t.assert.equal(response.status, 400);
    t.assert.equal(response.headers.get("content-type"), "application/json");

    const responseBody = await response.json();

    t.assert.equal(typeof responseBody, "object");
    t.assert.equal(responseBody.error, "invalid_request");
  });
});

describe("OAuth / POST /oauth/token (Public Client)", () => {
  let application: Schema.Application;
  let client: Awaited<ReturnType<typeof createOAuthApplication>>;
  let account: Awaited<ReturnType<typeof createAccount>>;

  beforeEach(async () => {
    account = await createAccount();
    client = await createOAuthApplication({
      scopes: ["read:accounts"],
      redirectUris: [OOB_REDIRECT_URI],
      confidential: false,
    });
    application = await getApplication(client);
  });

  afterEach(async () => {
    await cleanDatabase();
  });

  it(
    "can request an access token using the authorization code grant flow",
    { plan: 8 },
    async (t: TestContext) => {
      const accessGrant = await createAccessGrant(
        application.id,
        account.id,
        ["read:accounts"],
        OOB_REDIRECT_URI,
      );

      const body = new FormData();
      body.set("grant_type", "authorization_code");
      body.set("redirect_uri", OOB_REDIRECT_URI);
      body.set("code", accessGrant.code);

      const response = await app.request(
        `/oauth/token?client_id=${application.clientId}`,
        {
          method: "POST",
          body,
        },
      );

      const responseBody = await response.json();

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      const lastAccessToken = await getLastAccessToken();
      const changedAccessGrant = await findAccessGrant(accessGrant.code);

      t.assert.notEqual(
        changedAccessGrant.revoked,
        null,
        "Successfully revokes the access grant",
      );
      t.assert.equal(lastAccessToken.grant_type, "authorization_code");
      t.assert.deepStrictEqual(
        lastAccessToken.scopes,
        changedAccessGrant.scopes,
      );

      t.assert.equal(
        responseBody.access_token,
        lastAccessToken.code,
        "Generates an Access Token",
      );
      t.assert.equal(responseBody.token_type, "Bearer");
      t.assert.equal(responseBody.scope, lastAccessToken.scopes.join(" "));
    },
  );

  it(
    "cannot request an access token using the client credentials grant flow",
    { plan: 3 },
    async (t: TestContext) => {
      const body = new FormData();
      body.set("grant_type", "client_credentials");
      body.set("scope", "read:accounts");

      const response = await app.request(
        `/oauth/token?client_id=${application.clientId}`,
        {
          method: "POST",
          body,
        },
      );

      const responseBody = await response.json();

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");

      t.assert.equal(responseBody.error, "unauthorized_client");
    },
  );
});

describe("OAuth / POST /oauth/revoke", () => {
  let account: Awaited<ReturnType<typeof createAccount>>;
  let client: Awaited<ReturnType<typeof createOAuthApplication>>;
  let application: Schema.Application;
  let wrongClient: Awaited<ReturnType<typeof createOAuthApplication>>;
  let wrongApplication: Schema.Application;

  beforeEach(async () => {
    account = await createAccount();
    client = await createOAuthApplication({
      scopes: ["read:accounts"],
      redirectUris: [OOB_REDIRECT_URI],
      confidential: true,
    });
    application = await getApplication(client);

    wrongClient = await createOAuthApplication({
      scopes: ["read:accounts"],
      redirectUris: [OOB_REDIRECT_URI],
      confidential: true,
    });
    wrongApplication = await getApplication(wrongClient);
  });

  afterEach(async () => {
    await cleanDatabase();
  });

  it(
    "can revoke an access token using client_secret_basic",
    { plan: 4 },
    async (t: TestContext) => {
      const accessToken = await getAccessToken(client, account);
      const body = new FormData();
      body.set("token", accessToken.token);

      const response = await app.request("/oauth/revoke", {
        method: "POST",
        headers: {
          authorization: basicAuthorization(application),
        },
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const accessTokenAfterRevocation = await findAccessToken(
        accessToken.token,
      );

      t.assert.equal(accessTokenAfterRevocation, undefined);
    },
  );

  it(
    "can revoke an access token using client_secret_post",
    { plan: 4 },
    async (t: TestContext) => {
      const accessToken = await getAccessToken(client, account);
      const body = new FormData();
      body.set("token", accessToken.token);
      body.set("client_id", application.clientId);
      body.set("client_secret", application.clientSecret);

      const response = await app.request("/oauth/revoke", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const accessTokenAfterRevocation = await findAccessToken(
        accessToken.token,
      );

      t.assert.equal(accessTokenAfterRevocation, undefined);
    },
  );

  it(
    "cannot revoke an access token for a different client, but does not return any errors",
    { plan: 4 },
    async (t: TestContext) => {
      const accessToken = await getAccessToken(client, account);
      const body = new FormData();
      body.set("token", accessToken.token);
      body.set("client_id", wrongApplication.clientId);
      body.set("client_secret", wrongApplication.clientSecret);

      const response = await app.request("/oauth/revoke", {
        method: "POST",
        body,
      });

      t.assert.equal(response.status, 200);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const accessTokenAfterRevocation = await findAccessToken(
        accessToken.token,
      );

      t.assert.notEqual(accessTokenAfterRevocation, undefined);
    },
  );

  it(
    "cannot revoke a token using token_type_hint of refresh_token",
    { plan: 5 },
    async (t: TestContext) => {
      const body = new FormData();
      body.set("token", "123");
      body.set("token_type_hint", "refresh_token");

      const response = await app.request("/oauth/revoke", {
        method: "POST",
        headers: {
          authorization: basicAuthorization(application),
        },
        body,
      });

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const responseBody = await response.json();

      t.assert.equal(typeof responseBody, "object");
      t.assert.equal(responseBody.error, "unsupported_token_type");
    },
  );

  it(
    "cannot revoke a token without supplying the token parameter",
    { plan: 5 },
    async (t: TestContext) => {
      const body = new FormData();
      // explicitly doesn't have `token`
      body.set("token_type_hint", "refresh_token");

      const response = await app.request("/oauth/revoke", {
        method: "POST",
        headers: {
          authorization: basicAuthorization(application),
        },
        body,
      });

      t.assert.equal(response.status, 400);
      t.assert.equal(response.headers.get("content-type"), "application/json");
      t.assert.equal(response.headers.get("access-control-allow-origin"), "*");

      const responseBody = await response.json();

      t.assert.equal(typeof responseBody, "object");
      t.assert.equal(responseBody.error, "invalid_request");
    },
  );
});
