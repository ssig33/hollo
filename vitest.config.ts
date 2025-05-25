import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "dotenv";
import { defineConfig } from "vitest/config";

const env = parse(await readFile(join(process.cwd(), ".env.test")));

console.log(env);

export default defineConfig(() => ({
  test: {
    env: env,
    reporters: process.env.GITHUB_ACTIONS
      ? ["basic", "github-actions"]
      : ["default"],
    fileParallelism: false,
    expect: {
      requireAssertions: true,
    },
  },
}));
