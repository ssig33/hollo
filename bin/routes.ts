import { showRoutes } from "hono/dev";
import app from "../src/index";

showRoutes(app, {
  colorize: true,
});
