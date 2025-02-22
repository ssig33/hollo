import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { after } from "node:test";
import { serializeSigned } from "hono/utils/cookie";
import db from "../src/db";
import { drive } from "../src/storage";

const fixtureFiles = join(import.meta.dirname, "fixtures", "files");

export async function getFixtureFile(
  name: string,
  type: string,
): Promise<File> {
  const filePath = join(fixtureFiles, name);
  const data = await readFile(filePath);

  return new File([data], name, {
    type,
  });
}

// biome-ignore lint/complexity/useLiteralKeys: tsc complains about this (TS4111)
const SECRET_KEY = process.env["SECRET_KEY"];

export async function getLoginCookie() {
  // Same logic as in src/pages/login.tsx
  return serializeSigned("login", new Date().toISOString(), SECRET_KEY!, {
    path: "/",
  });
}

// Automatically close the database and remove test file uploads
// Without this the tests hang due to the database
after(async () => {
  await db.$client.end({ timeout: 5 });

  const disk = drive.fake();
  await disk.deleteAll();
});
