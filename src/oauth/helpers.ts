import { base64 } from "@hexagon/base64";
import { getLogger } from "@logtape/logtape";

import db from "../db";
import { SECRET_KEY } from "../env";
import * as schema from "../schema";
import type { Uuid } from "../uuid";

const logger = getLogger(["hollo", "oauth"]);

export async function createAuthorizationCode(
  application_id: Uuid,
  account_id: Uuid,
  scopes: schema.Scope[],
): Promise<string> {
  const code = base64.fromArrayBuffer(
    crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer,
    true,
  );

  await db.insert(schema.accessTokens).values({
    accountOwnerId: account_id,
    code,
    applicationId: application_id,
    scopes: scopes,
  });

  return code;
}

export type AuthorizationCodeVerification =
  | { verified: true; code: string }
  | {
      verified: false;
      error_description: string;
    };

export async function verifyAuthorizationCode(
  token: string,
): Promise<AuthorizationCodeVerification> {
  const values = token.split("^");
  if (values.length !== 3) {
    return {
      verified: false,
      error_description: "invalid authorization code",
    };
  }

  const [signature, created, code] = values;
  const textEncoder = new TextEncoder();
  const sig = base64.toArrayBuffer(signature, true);

  try {
    const secretKey = await crypto.subtle.importKey(
      "raw",
      textEncoder.encode(SECRET_KEY),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );

    const verified = await crypto.subtle.verify(
      { name: "HMAC", hash: "SHA-256" },
      secretKey,
      sig,
      textEncoder.encode(`${created}^${code}`),
    );

    if (!verified) {
      return {
        verified: false,
        error_description: "invalid authorization code",
      };
    }

    return { verified: true, code: code };
  } catch (err) {
    logger.error("Error verifying authorization code", { error: err });

    return {
      verified: false,
      error_description: "invalid authorization code",
    };
  }
}

export type AuthorizationError = {
  error: string;
  error_description: string;
};

export type AccessToken = {
  token: string;
  type: "Bearer";
  scope: string;
  createdAt: number;
};

export type AuthorizationGrant = schema.AccessToken;

export async function createAccessToken(
  authorization_grant: AuthorizationGrant,
): Promise<AccessToken> {
  const now = (Date.now() / 1000) | 0;
  const message = `${now}^${authorization_grant.code}`;
  const textEncoder = new TextEncoder();
  const secretKey = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(SECRET_KEY),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    secretKey,
    textEncoder.encode(message),
  );

  return {
    token: `${base64.fromArrayBuffer(signature, true)}^${message}`,
    type: "Bearer",
    scope: authorization_grant.scopes.join(" "),
    createdAt: now,
  };
}

export async function createClientCredential(
  application: schema.Application,
  scopes?: schema.Scope[],
): Promise<AccessToken> {
  const code = base64.fromArrayBuffer(
    crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer,
    true,
  );

  const result = await db
    .insert(schema.accessTokens)
    .values({
      code,
      applicationId: application.id,
      scopes: scopes ?? application.scopes,
      grant_type: "client_credentials",
    })
    .returning();

  // This would only happen if by some amazing luck we managed to generate two
  // of the exact same `code` values:
  if (result.length !== 1) {
    throw new Error(
      "We were unable to create a client credential access token at this time.",
    );
  }

  return {
    token: result[0].code,
    type: "Bearer",
    scope: result[0].scopes.join(" "),
    createdAt: (+result[0].created / 1000) | 0,
  };
}
