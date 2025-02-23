import { Hono } from "hono";
import { deleteCookie } from "hono/cookie";

const logout = new Hono();

logout.post("/", async (c) => {
  await deleteCookie(c, "login");
  return c.redirect("/");
});

export default logout;
