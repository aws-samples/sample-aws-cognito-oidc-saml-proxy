# Custom login pages

Amazon Cognito Managed Login is the sign-in page behind a user pool's OAuth 2.0 endpoints.
If you build your own sign-in UI that calls the user pool API directly (for example
`InitiateAuth`), the app receives tokens without going through `/oauth2/authorize`: there is
no authorization code flow and no Managed Login session to give single sign-on across apps.

The gateway lets each application use a custom login page while the SAML or OIDC flow stays
standard.

## How the flow works

1. An app starts a SAML or OIDC sign-in at the gateway.
2. The gateway records a single-use pending login and redirects the browser to the app's
   custom login URL, adding `return_to` and `state` query parameters. The redirect also sets
   a short-lived `__Host-` cookie that binds the flow to this browser (see
   [Browser binding](../protocols/saml.md#custom-login-and-idp-initiated-sso) and
   [Security](../overview/security.md)).
3. Your page signs the user in against the app's identity source (a Cognito user pool), with
   any UI and any Cognito sign-in flow.
4. The page posts the Cognito ID token (`id_token`) and `state` to `return_to`:
   `/t/{tenant}/saml/login/complete` or `/t/{tenant}/oidc/login/complete`.
5. The gateway verifies the token's signature against the pool's JWKS and checks that its
   audience is the identity source's app client, then completes the SAML response or the
   OIDC authorization code as usual.

## Configure an application

In the console, open the application's **Custom Login Page** section and set:

- **Custom login URL**: the page the gateway redirects to (`customLoginUrl` in the
  management API).
- **Trusted login redirect URLs**: the allow-list of login-page URLs (https). The custom
  login URL must match one of them (`trustedLoginRedirectUris`).

Applications without a custom login URL keep using Managed Login.

## Keep Cognito's own OAuth endpoints

Apps that talk to a Cognito user pool directly can get a custom login page too. Register
that user pool in the gateway as a SAML application, and add the gateway to the pool as a
SAML identity provider:

- In the gateway, register a SAML app with the pool's SP entity ID
  `urn:amazon:cognito:sp:<user-pool-id>` and ACS URL
  `https://<user-pool-domain>/saml2/idpresponse`, keep the default persistent NameID (the
  user's `sub`, which never changes), and set the app's custom login page.
- In the user pool,
  [add a SAML identity provider](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-saml-idp.html)
  from that app's metadata URL (`/t/{tenant}/saml/metadata/{appId}`) and enable it on the
  app clients.

Apps keep calling the user pool's `/oauth2/authorize` and `/oauth2/token` endpoints (pass
`identity_provider=<provider-name>` to go straight to the gateway). Cognito sends the
sign-in to the gateway, the gateway sends the user to your page, and Cognito issues its own
tokens and Managed Login session. Users who sign in this way are federated users of that
pool.

## IdP-initiated launches

An app launcher can post a Cognito ID token and the target SAML app's `entityId` to
`/t/{tenant}/saml/idp-initiate` to start IdP-initiated SSO. This is off by default; enable
**Allow IdP-initiated SSO** per app. A browser form post is accepted only from the
gateway's own origin or the origin of the app's custom login URL or trusted login redirect
URLs, so list the launcher page there (see [Security](../overview/security.md)).

## Example

The [`examples/custom-ui`](https://github.com/aws-samples/sample-aws-cognito-oidc-saml-proxy/tree/main/examples/custom-ui)
app implements a custom login page and a launcher.
