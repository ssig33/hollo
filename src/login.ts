import { getSignedCookie } from "hono/cookie";
import { createMiddleware } from "hono/factory";
import { db } from "./db";
import { SECRET_KEY } from "./env";

export const loginRequired = createMiddleware(async (c, next) => {
  const login = await getSignedCookie(c, SECRET_KEY, "login");
  if (login == null || login === false) {
    return c.redirect(`/login?next=${encodeURIComponent(c.req.url)}`);
  }
  const totp = await db.query.totps.findFirst();
  if (totp != null) {
    const otp = await getSignedCookie(c, SECRET_KEY, "otp");
    if (otp == null || otp === false || otp !== `${login} totp`) {
      return c.redirect(`/login/otp?next=${encodeURIComponent(c.req.url)}`);
    }
  }
  await next();
});
