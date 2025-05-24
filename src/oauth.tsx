import { zValidator } from "@hono/zod-validator";
import { getLogger } from "@logtape/logtape";
import { and, eq } from "drizzle-orm";
import { escape } from "es-toolkit";
import { type Context, Hono } from "hono";
import { cors } from "hono/cors";
import { z } from "zod";
import { Layout } from "./components/Layout";
import { db } from "./db";
import { requestBody } from "./helpers";
import { loginRequired } from "./login";
import { OOB_REDIRECT_URI } from "./oauth/constants";
import {
  createAccessGrant,
  createAccessToken,
  createClientCredential,
} from "./oauth/helpers";
import {
  type ClientAuthenticationVariables,
  clientAuthentication,
} from "./oauth/middleware";
import { scopesSchema } from "./oauth/validators";
import {
  type Account,
  type AccountOwner,
  type Application,
  type Scope,
  accessGrants,
  accessTokens,
  applications,
  scopeEnum,
} from "./schema";
import { renderCustomEmojis } from "./text";
import { uuid } from "./uuid";

const logger = getLogger(["hollo", "oauth"]);

const app = new Hono<{ Variables: ClientAuthenticationVariables }>();

app.get(
  "/authorize",
  zValidator(
    "query",
    z.object({
      response_type: z.enum(["code"]),
      client_id: z.string(),
      redirect_uri: z.string().url(),
      scope: scopesSchema.optional(),
      state: z.string().optional(),
    }),
  ),
  loginRequired,
  async (c) => {
    const data = c.req.valid("query");
    const application = await db.query.applications.findFirst({
      where: eq(applications.clientId, data.client_id),
    });
    if (application == null) return c.json({ error: "invalid_client_id" }, 400);
    const scopes = data.scope ?? ["read"];
    if (scopes.some((s) => !application.scopes.includes(s))) {
      return c.json({ error: "invalid_scope" }, 400);
    }
    if (!application.redirectUris.includes(data.redirect_uri)) {
      return c.json({ error: "invalid_redirect_uri" }, 400);
    }
    const accountOwners = await db.query.accountOwners.findMany({
      with: { account: true },
    });
    return c.html(
      <AuthorizationPage
        accountOwners={accountOwners}
        application={application}
        redirectUri={data.redirect_uri}
        scopes={scopes}
        state={data.state}
      />,
    );
  },
);

interface AuthorizationPageProps {
  accountOwners: (AccountOwner & { account: Account })[];
  application: Application;
  redirectUri: string;
  scopes: Scope[];
  state?: string;
}

function AuthorizationPage(props: AuthorizationPageProps) {
  return (
    <Layout title={`Hollo: Authorize ${props.application.name}`}>
      <hgroup>
        <h1>Authorize {props.application.name}</h1>
        <p>Do you want to authorize this application to access your account?</p>
      </hgroup>
      <p>It allows the application to:</p>
      <ul>
        {props.scopes.map((scope) => (
          <li key={scope}>
            <code>{scope}</code>
          </li>
        ))}
      </ul>
      <form action="/oauth/authorize" method="post">
        <p>Choose an account to authorize:</p>
        {props.accountOwners.map((accountOwner, i) => {
          const accountName = renderCustomEmojis(
            escape(accountOwner.account.name),
            accountOwner.account.emojis,
          );
          return (
            <label>
              <input
                type="radio"
                name="account_id"
                value={accountOwner.id}
                checked={i === 0}
              />
              {/* biome-ignore lint/security/noDangerouslySetInnerHtml: xss protected */}
              <strong dangerouslySetInnerHTML={{ __html: accountName }} />
              <p style="margin-left: 1.75em; margin-top: 0.25em;">
                <small>{accountOwner.account.handle}</small>
              </p>
            </label>
          );
        })}
        <input
          type="hidden"
          name="application_id"
          value={props.application.id}
        />
        <input type="hidden" name="redirect_uri" value={props.redirectUri} />
        <input type="hidden" name="scopes" value={props.scopes.join(" ")} />
        {props.state != null && (
          <input type="hidden" name="state" value={props.state} />
        )}
        <div role="group">
          {props.redirectUri !== "urn:ietf:wg:oauth:2.0:oob" && (
            <button
              type="submit"
              class="secondary"
              name="decision"
              value="deny"
            >
              Deny
            </button>
          )}
          <button type="submit" name="decision" value="allow">
            Allow
          </button>
        </div>
      </form>
    </Layout>
  );
}

app.post(
  "/authorize",
  loginRequired,
  zValidator(
    "form",
    z.object({
      account_id: uuid,
      application_id: uuid,
      redirect_uri: z.string().url(),
      scopes: scopesSchema,
      state: z.string().optional(),
      decision: z.enum(["allow", "deny"]),
    }),
  ),
  async (c) => {
    const form = c.req.valid("form");
    const application = await db.query.applications.findFirst({
      where: eq(applications.id, form.application_id),
    });
    if (application == null) {
      return c.notFound();
    }

    const accountOwner = await db.query.accountOwners.findFirst({
      where: eq(applications.id, form.account_id),
    });
    if (accountOwner == null) {
      return c.notFound();
    }

    if (form.scopes.some((s) => !application.scopes.includes(s))) {
      return c.json({ error: "invalid_scope" }, 400);
    }

    if (!application.redirectUris.includes(form.redirect_uri)) {
      return c.json({ error: "invalid_redirect_uri" }, 400);
    }

    const url = new URL(form.redirect_uri);
    if (form.decision === "deny") {
      url.searchParams.set("error", "access_denied");
      url.searchParams.set(
        "error_description",
        "The resource owner or authorization server denied the request.",
      );
    } else {
      const accessGrant = await createAccessGrant(
        application.id,
        accountOwner.id,
        form.scopes,
        form.redirect_uri,
      );

      if (form.redirect_uri === OOB_REDIRECT_URI) {
        return c.html(
          <AuthorizationCodePage
            application={application}
            code={accessGrant.code}
          />,
        );
      }

      url.searchParams.set("code", accessGrant.code);

      if (form.state != null) {
        url.searchParams.set("state", form.state);
      }
    }
    return c.redirect(url.href);
  },
);

interface AuthorizationCodePageProps {
  application: Application;
  code: string;
}

function AuthorizationCodePage(props: AuthorizationCodePageProps) {
  return (
    <Layout title={"Hollo: Authorization Code"}>
      <hgroup>
        <h1>Authorization Code</h1>
        <p>Here is your authorization code.</p>
      </hgroup>
      <pre>{props.code}</pre>
      <p>
        Copy this code and paste it into <em>{props.application.name}</em>.
      </p>
    </Layout>
  );
}

const INVALID_GRANT_ERROR_DESCRIPTION =
  "The provided authorization code is invalid, expired, revoked, " +
  "does not match the redirection URI used in the authorization " +
  "request, or was issued to another client.";

const tokenRequestSchema = z.discriminatedUnion("grant_type", [
  z.strictObject({
    grant_type: z.literal("client_credentials"),
    scope: scopesSchema.optional(),
    // client_id and client_secret are present but consumed by the
    // clientAuthentication middleware:
    client_id: z.string().optional(),
    client_secret: z.string().optional(),
  }),
  z.strictObject({
    grant_type: z.literal("authorization_code"),
    redirect_uri: z.string().url(),
    code: z.string(),
    // client_id and client_secret are present but consumed by the
    // clientAuthentication middleware:
    client_id: z.string().optional(),
    client_secret: z.string().optional(),
  }),
]);

app.post("/token", cors(), clientAuthentication, async (c) => {
  const client = c.get("client");
  const result = await requestBody(c.req, tokenRequestSchema);

  if (!result.success) {
    if (
      result.error.errors.length === 1 &&
      result.error.errors[0].code === "invalid_union_discriminator"
    ) {
      return c.json(
        {
          error: "unsupported_grant_type",
          error_description:
            "The authorization grant type is not supported by the authorization server.",
        },
        400,
      );
    }

    return c.json({ error: "invalid_request", zod_error: result.error }, 400);
  }

  const form = result.data;
  if (form.grant_type === "authorization_code") {
    const authorizationCode = form.code;

    return await db
      .transaction(
        async (tx) => {
          const accessGrantResult = await tx
            .select()
            .from(accessGrants)
            .for("update")
            .where(eq(accessGrants.code, authorizationCode))
            .limit(1);

          const accessGrant = accessGrantResult[0];

          if (
            accessGrant === undefined ||
            accessGrant.applicationId !== client.id ||
            accessGrant?.revoked !== null
          ) {
            return c.json(
              {
                error: "invalid_grant",
                error_description: INVALID_GRANT_ERROR_DESCRIPTION,
              },
              400,
            );
          }

          const notAfter =
            accessGrant.created.valueOf() + accessGrant.expiresIn;
          if (Date.now() > notAfter) {
            return c.json(
              {
                error: "invalid_grant",
                error_description: INVALID_GRANT_ERROR_DESCRIPTION,
              },
              400,
            );
          }

          if (accessGrant.redirectUri !== form.redirect_uri) {
            return c.json(
              {
                error: "invalid_grant",
                error_description: INVALID_GRANT_ERROR_DESCRIPTION,
              },
              400,
            );
          }

          // Revoke the access grant:
          await tx
            .update(accessGrants)
            .set({
              revoked: new Date(),
            })
            .where(eq(accessGrants.id, accessGrant.id));

          // create the access token
          const accessToken = await createAccessToken(accessGrant, tx);

          if (accessToken === undefined) {
            return c.json(
              {
                error: "server_error",
                error_description:
                  "We could not issue an access token at this time",
              },
              500,
            );
          }

          return c.json(
            {
              access_token: accessToken.token,
              token_type: accessToken.type,
              scope: accessToken.scope,
              created_at: accessToken.created,
            },
            200,
          );
        },
        {
          accessMode: "read write",
          isolationLevel: "serializable",
          deferrable: true,
        },
      )
      .catch((err) => {
        logger.error("An unknown error occurred", err);

        return c.json(
          {
            error: "server_error",
            error_description:
              "We could not issue an access token at this time",
          },
          500,
        );
      });
  }

  if (form.grant_type === "client_credentials") {
    // Public clients cannot use the client_credentials grant flow
    if (!client.confidential) {
      return c.json(
        {
          error: "unauthorized_client",
          error_description:
            "The authenticated client is not authorized to use this authorization grant type.",
        },
        400,
      );
    }

    if (form.scope?.some((s) => !client.scopes.includes(s))) {
      return c.json(
        {
          error: "invalid_scope",
          error_description:
            "The requested scope is invalid, unknown, or malformed.",
        },
        400,
      );
    }

    const clientCredential = await createClientCredential(client, form.scope);

    return c.json({
      access_token: clientCredential.token,
      token_type: clientCredential.type,
      scope: clientCredential.scope,
      created_at: clientCredential.created,
    });
  }
});

// RFC7009 - OAuth Token Revocation:
const tokenRevocationSchema = z.strictObject({
  token: z.string(),
  token_type_hint: z.string().optional(),
  // client_id and client_secret are present but consumed by the
  // clientAuthentication middleware:
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
});

app.post("/revoke", cors(), clientAuthentication, async (c) => {
  const client = c.get("client");
  const result = await requestBody(c.req, tokenRevocationSchema);

  if (!result.success) {
    return c.json({ error: "invalid_request", zod_error: result.error }, 400);
  }

  if (
    result.data.token_type_hint &&
    result.data.token_type_hint !== "access_token"
  ) {
    return c.json(
      {
        error: "unsupported_token_type",
        error_description:
          "The authorization server does not support the revocation of the presented token type",
      },
      400,
    );
  }

  await db
    .delete(accessTokens)
    .where(
      and(
        eq(accessTokens.code, result.data.token),
        eq(accessTokens.applicationId, client.id),
      ),
    );

  // The spec is a little strange here in that the response status is 200, but
  // there's actually no response body, so 204 would be more appropriate.
  // We return an empty json response to make testing easier:
  return c.json({}, 200);
});

export async function oauthAuthorizationServer(c: Context) {
  const url = new URL(c.req.url);

  return c.json({
    issuer: new URL("/", url).href,
    authorization_endpoint: new URL("/oauth/authorize", url).href,
    token_endpoint: new URL("/oauth/token", url).href,
    // Not yet supported by Hollo:
    // "revocation_endpoint": "",
    scopes_supported: scopeEnum.enumValues,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "client_credentials"],
    token_endpoint_auth_methods_supported: [
      "client_secret_post",
      "client_secret_basic",
      // Not supported until we support public clients:
      // "none",
    ],
    app_registration_endpoint: new URL("/api/v1/apps", url).href,
  });
}

export default app;
