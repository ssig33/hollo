import { exportJwk, generateCryptoKeyPair } from "@fedify/fedify";
import { base64 } from "@hexagon/base64";
import { eq } from "drizzle-orm";

import db from "../../src/db";
import * as Schema from "../../src/schema";

import {
  createAccessToken,
  createAuthorizationCode,
} from "../../src/oauth/helpers";

export async function createAccount() {
  const [account] = await db.transaction(async (tx) => {
    await tx
      .insert(Schema.instances)
      .values({
        host: "http://hollo.test",
        software: "hollo",
        softwareVersion: null,
      })
      .onConflictDoNothing();
    const account = await tx
      .insert(Schema.accounts)
      .values({
        id: crypto.randomUUID(),
        iri: "http://hollo.test/@hollo",
        instanceHost: "http://hollo.test",
        type: "Person",
        name: "Hollo Test",
        emojis: {},
        handle: "@hollo@hollo.test",
        bioHtml: "",
        url: "https://hollo.test/@hollo",
        protected: false,
        inboxUrl: "https://hollo.test/@hollo/inbox",
        followersUrl: "https://hollo.test/@hollo/followers",
        sharedInboxUrl: "https://hollo.test/inbox",
        featuredUrl: "https://hollo.test/@hollo/pinned",
        published: new Date(),
      })
      .returning();

    const rsaKeyPair = await generateCryptoKeyPair("RSASSA-PKCS1-v1_5");
    const ed25519KeyPair = await generateCryptoKeyPair("Ed25519");

    const owner = await tx
      .insert(Schema.accountOwners)
      .values({
        id: account[0].id,
        handle: "hollo",
        rsaPrivateKeyJwk: await exportJwk(rsaKeyPair.privateKey),
        rsaPublicKeyJwk: await exportJwk(rsaKeyPair.publicKey),
        ed25519PrivateKeyJwk: await exportJwk(ed25519KeyPair.privateKey),
        ed25519PublicKeyJwk: await exportJwk(ed25519KeyPair.publicKey),
        bio: "",
        language: "en",
        visibility: "public",
        themeColor: "amber",
        discoverable: false,
      })
      .returning();

    return [account[0], owner[0]];
  });

  return account;
}

export type OAuthApplicationOptions = {
  scopes?: Schema.Scope[];
  redirectUris?: string[];
};

export async function createOAuthApplication(
  options: OAuthApplicationOptions = {},
): Promise<Schema.Application> {
  const clientId = base64.fromArrayBuffer(
    crypto.getRandomValues(new Uint8Array(16)).buffer as ArrayBuffer,
    true,
  );
  const clientSecret = base64.fromArrayBuffer(
    crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer,
    true,
  );

  const app = await db
    .insert(Schema.applications)
    .values({
      id: crypto.randomUUID(),
      name: "Test Application",
      redirectUris: options.redirectUris ?? [],
      scopes: options.scopes ?? [],
      website: "",
      clientId,
      clientSecret,
    } satisfies Schema.NewApplication)
    .returning();

  return app[0];
}

export async function getAccessToken(
  client: Schema.Application,
  account: Schema.Account,
  scopes: Schema.Scope[] = [],
) {
  const code = await createAuthorizationCode(client.id, account.id, scopes);

  const authorizationGrant = await db.query.accessTokens.findFirst({
    where: eq(Schema.accessTokens.code, code),
    with: {
      accountOwner: { with: { account: { with: { successor: true } } } },
      application: true,
    },
  });

  const accessToken = await createAccessToken(authorizationGrant!);

  return {
    authorizationHeader: `${accessToken.type} ${accessToken.token}`,
    scopes: accessToken.scope.split(" "),
  };
}
