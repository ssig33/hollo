import { describe, expect, it } from "vitest";

import app from "./index";

describe("Router", () => {
  describe("CORS Policy", () => {
    // Note: The API CORS Policy is defined in src/api/index.ts

    it("returns CORS headers on /.well-known/oauth-authorization-server", async () => {
      expect.assertions(4);

      const response = await app.request(
        "/.well-known/oauth-authorization-server",
        {
          method: "OPTIONS",
        },
      );

      expect(response.headers.has("access-control-allow-origin")).toBeTruthy();
      expect(response.headers.get("access-control-allow-origin")).toBe("*");

      expect(response.headers.has("access-control-allow-methods")).toBeTruthy();
      expect(response.headers.get("access-control-allow-methods")).toBe("GET");
    });

    it("returns CORS headers on /nodeinfo/2.1", async () => {
      expect.assertions(4);

      const response = await app.request("/nodeinfo/2.1", {
        method: "OPTIONS",
      });

      expect(response.headers.has("access-control-allow-origin")).toBeTruthy();
      expect(response.headers.get("access-control-allow-origin")).toBe("*");

      expect(response.headers.has("access-control-allow-methods")).toBeTruthy();
      expect(response.headers.get("access-control-allow-methods")).toBe("GET");
    });

    it("does not return CORS headers on /oauth/authorize", async () => {
      expect.assertions(2);

      const response = await app.request("/oauth/authorize", {
        method: "OPTIONS",
      });

      expect(response.headers.has("access-control-allow-origin")).toBeFalsy();
      expect(response.headers.has("access-control-allow-methods")).toBeFalsy();
    });

    it("returns CORS headers on /oauth/token", async () => {
      expect.assertions(4);

      const response = await app.request("/oauth/token", {
        method: "OPTIONS",
      });

      expect(response.headers.has("access-control-allow-origin")).toBeTruthy();
      expect(response.headers.get("access-control-allow-origin")).toBe("*");

      expect(response.headers.has("access-control-allow-methods")).toBeTruthy();
      expect(response.headers.get("access-control-allow-methods")).toBe("POST");
    });

    it("returns CORS headers on /oauth/revoke", async () => {
      expect.assertions(4);

      const response = await app.request("/oauth/revoke", {
        method: "OPTIONS",
      });

      expect(response.headers.has("access-control-allow-origin")).toBeTruthy();
      expect(response.headers.get("access-control-allow-origin")).toBe("*");

      expect(response.headers.has("access-control-allow-methods")).toBeTruthy();
      expect(response.headers.get("access-control-allow-methods")).toBe("POST");
    });

    it("returns CORS headers on GET /oauth/userinfo", async () => {
      expect.assertions(4);

      const response = await app.request("/oauth/userinfo", {
        method: "OPTIONS",
      });

      expect(response.headers.has("access-control-allow-origin")).toBeTruthy();
      expect(response.headers.get("access-control-allow-origin")).toBe("*");

      expect(response.headers.has("access-control-allow-methods")).toBeTruthy();
      expect(response.headers.get("access-control-allow-methods")).toBe(
        "GET,POST",
      );
    });
  });
});
