import { describe, expect, it } from "vitest";
import {
  calculatePKCECodeChallenge,
  generatePKCECodeVerifier,
} from "./helpers";

import { URL_SAFE_REGEXP } from "../helpers";

describe("OAuth Helpers", () => {
  describe("generatePKCECodeVerifier", () => {
    it("returns a URL safe string", () => {
      const codeVerifier = generatePKCECodeVerifier();
      expect(codeVerifier).to.match(URL_SAFE_REGEXP);
    });
  });

  describe("calculatePKCECodeChallenge", () => {
    it("should not throw any errors", async () => {
      expect.assertions(1);
      expect(async () => {
        await calculatePKCECodeChallenge("testtest");
      }).not.toThrow();
    });

    it("should return a URL safe string", async () => {
      expect.assertions(1);

      const code = await calculatePKCECodeChallenge("testtest");

      expect(code).toBe("NyaDNd1pMQRb3N-SYj_4GaZCRLU9DnRtQ4eXNJ1NpXg");
    });
  });
});
