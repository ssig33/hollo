import type { HonoRequest } from "hono";
import type z from "zod";

export async function requestBody<T extends z.ZodType = z.ZodTypeAny>(
  req: HonoRequest,
  schema: T,
  // biome-ignore lint/suspicious/noExplicitAny: Input type is `any` as it comes from the request
): Promise<z.SafeParseReturnType<any, z.output<T>>> {
  const contentType = req.header("Content-Type");
  if (
    contentType === "application/json" ||
    contentType?.match(/^application\/json\s*;/)
  ) {
    const json = await req.json();
    return await schema.safeParseAsync(json);
  }

  const formData = await req.parseBody();
  return await schema.safeParseAsync(formData);
}
