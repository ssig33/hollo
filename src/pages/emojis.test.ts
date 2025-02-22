import { afterEach, beforeEach, describe, it } from "node:test";
import type { TestContext } from "node:test";

import { getFixtureFile, getLoginCookie } from "../../tests/helpers";

import db from "../db";
import { customEmojis } from "../schema";

import { drive } from "../storage";
import app from "./index";

const emojiFile = await getFixtureFile("emoji.png", "image/png");

describe("emojis", () => {
  beforeEach(async () => {
    await db.delete(customEmojis);
  });

  afterEach(() => {
    drive.restore();
  });

  it("Successfully saves a new emoji", async (t: TestContext) => {
    const disk = drive.fake();
    const testShortCode = ":test-emoji:";

    const formData = new FormData();
    formData.append("shortcode", testShortCode);
    formData.append("image", emojiFile);

    const cookie = await getLoginCookie();

    const response = await app.request("/emojis", {
      method: "POST",
      body: formData,
      headers: {
        Cookie: cookie,
      },
    });

    t.assert.equal(response.status, 302);
    t.assert.equal(response.headers.get("Location"), "/emojis");

    // Assert we uploaded the file:
    t.assert.doesNotThrow(() => disk.assertExists("emojis/test-emoji.png"));

    const emoji = await db.query.customEmojis.findFirst();

    t.assert.ok(emoji, "Successfully saves the emoji");
    t.assert.equal(emoji.category, null, "Defaults category to null");
    t.assert.equal(
      emoji.url,
      "http://hollo.test/assets/emojis/test-emoji.png",
      "Sets the file URL correctly",
    );
    t.assert.equal(emoji.shortcode, "test-emoji");
  });
});
