import { beforeEach, describe, expect, it } from "vitest";

import { cleanDatabase } from "../../../tests/helpers";
import {
  bearerAuthorization,
  createAccount,
  createOAuthApplication,
  getAccessToken,
  getApplication,
} from "../../../tests/helpers/oauth";

import app from "../../index";

describe.sequential("/api/v1/accounts/verify_credentials", () => {
  let client: Awaited<ReturnType<typeof createOAuthApplication>>;
  let account: Awaited<ReturnType<typeof createAccount>>;
  let application: Awaited<ReturnType<typeof getApplication>>;
  let accessToken: Awaited<ReturnType<typeof getAccessToken>>;

  beforeEach(async () => {
    await cleanDatabase();

    account = await createAccount({ generateKeyPair: true });
    client = await createOAuthApplication({
      scopes: ["write"],
    });
    application = await getApplication(client);
    accessToken = await getAccessToken(client, account, ["write"]);
  });

  it("Successfully creates a new status with a valid access token using JSON", async () => {
    expect.assertions(7);

    const body = JSON.stringify({
      status: "Hello world",
      media_ids: [],
    });

    const response = await app.request("/api/v1/statuses", {
      method: "POST",
      headers: {
        authorization: bearerAuthorization(accessToken),
        "Content-Type": "application/json",
      },
      body: body,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("access-control-allow-origin")).toBe("*");

    const json = await response.json();

    expect(typeof json).toBe("object");
    expect(json.content).toBe("<p>Hello world</p>\n");
    expect(json.account.id).toBe(account.id);
    expect(json.application.name).toBe(application.name);
  });

  it("Successfully creates a new status with a valid access token using FormData", async () => {
    expect.assertions(7);

    const body = new FormData();
    body.append("status", "Hello world");

    const response = await app.request("/api/v1/statuses", {
      method: "POST",
      headers: {
        authorization: bearerAuthorization(accessToken),
      },
      body: body,
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("access-control-allow-origin")).toBe("*");

    const json = await response.json();

    expect(typeof json).toBe("object");
    expect(json.content).toBe("<p>Hello world</p>\n");
    expect(json.account.id).toBe(account.id);
    expect(json.application.name).toBe(application.name);
  });

  it("Can update a status using JSON", async () => {
    const body = JSON.stringify({
      status: "Hello world",
    });

    const createResponse = await app.request("/api/v1/statuses", {
      method: "POST",
      headers: {
        authorization: bearerAuthorization(accessToken),
        "Content-Type": "application/json",
      },
      body: body,
    });

    expect(createResponse.status).toBe(200);
    expect(createResponse.headers.get("content-type")).toBe("application/json");

    const createJson = await createResponse.json();
    const id = createJson.id;

    expect(id).not.toBeNull();

    const updateBody = JSON.stringify({
      status: "Test Update",
    });
    const updateResponse = await app.request(`/api/v1/statuses/${id}`, {
      method: "PUT",
      headers: {
        authorization: bearerAuthorization(accessToken),
        "Content-Type": "application/json",
      },
      body: updateBody,
    });

    expect(updateResponse.status).toBe(200);
    expect(updateResponse.headers.get("content-type")).toBe("application/json");
    expect(updateResponse.headers.get("access-control-allow-origin")).toBe("*");

    const updateJson = await updateResponse.json();

    expect(typeof updateJson).toBe("object");
    expect(updateJson.content).toBe("<p>Test Update</p>\n");
  });

  it("Can update a status using FormData", async () => {
    const body = JSON.stringify({
      status: "Hello world",
      media_ids: [],
    });

    const createResponse = await app.request("/api/v1/statuses", {
      method: "POST",
      headers: {
        authorization: bearerAuthorization(accessToken),
        "Content-Type": "application/json",
      },
      body: body,
    });

    expect(createResponse.status).toBe(200);
    expect(createResponse.headers.get("content-type")).toBe("application/json");

    const createJson = await createResponse.json();
    const id = createJson.id;

    expect(id).not.toBeNull();

    const updateBody = new FormData();
    updateBody.append("status", "Test Update");
    const updateResponse = await app.request(`/api/v1/statuses/${id}`, {
      method: "PUT",
      headers: {
        authorization: bearerAuthorization(accessToken),
      },
      body: updateBody,
    });

    expect(updateResponse.status).toBe(200);
    expect(updateResponse.headers.get("content-type")).toBe("application/json");
    expect(updateResponse.headers.get("access-control-allow-origin")).toBe("*");

    const updateJson = await updateResponse.json();

    expect(typeof updateJson).toBe("object");
    expect(updateJson.content).toBe("<p>Test Update</p>\n");
  });
});
