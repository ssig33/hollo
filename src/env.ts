const SECRET_KEY_MINIMUM_LENGTH = 44;

// biome-ignore lint/complexity/useLiteralKeys: tsc complains about this (TS4111)
const secretKey = process.env["SECRET_KEY"];

if (typeof secretKey !== "string") {
  throw new Error("SECRET_KEY is required");
}

if (secretKey.length < SECRET_KEY_MINIMUM_LENGTH) {
  throw new Error(
    `SECRET_KEY is too short, received: ${secretKey.length}, expected: ${SECRET_KEY_MINIMUM_LENGTH}`,
  );
}

export const SECRET_KEY = secretKey;
