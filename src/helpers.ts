import type { HonoRequest } from "hono";
import type { SafeParseReturnType, ZodType, ZodTypeDef, output } from "zod";

// biome-ignore lint/suspicious/noExplicitAny: <explanation>
export async function requestBody<T extends ZodType<any, ZodTypeDef, any>>(
  req: HonoRequest,
  schema: T,
  // biome-ignore lint/suspicious/noExplicitAny: <explanation>
): Promise<SafeParseReturnType<any, output<T>>> {
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
