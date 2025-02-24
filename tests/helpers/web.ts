import { serializeSigned } from "hono/utils/cookie";
import { SECRET_KEY } from "../../src/env";

export async function getLoginCookie() {
  // Same logic as in src/pages/login.tsx
  return serializeSigned("login", new Date().toISOString(), SECRET_KEY!, {
    path: "/",
  });
}
