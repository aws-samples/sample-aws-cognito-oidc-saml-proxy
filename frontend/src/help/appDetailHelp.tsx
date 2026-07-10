import type { HelpContent } from '../contexts/HelpPanelContext';

// Contextual help for the Application detail page tabs (Overview, Protocol,
// Custom login, Integration). Content reflects the gateway's actual behavior.

export const appOverviewHelp: HelpContent = {
  header: <h2>Application</h2>,
  content: (
    <div>
      <p>
        An <strong>application</strong> is a relying party (SAML SP or OIDC RP) that the
        gateway federates users into. It is bound to one <strong>identity source</strong> (a
        Cognito user pool) that authenticates the user; the gateway then issues a SAML
        assertion or OIDC token to the application.
      </p>
      <h3>Tabs</h3>
      <ul>
        <li><strong>Overview</strong> — identity, protocol, status, and bound source.</li>
        <li><strong>Protocol</strong> — SAML or OIDC settings (endpoints, signing, lifetimes).</li>
        <li><strong>Custom login</strong> — optionally replace the Cognito Hosted UI with your own login page.</li>
        <li><strong>Mappings</strong> — claim and role mappings released to the app.</li>
        <li><strong>Integration</strong> — copy/paste endpoints, certificate, and quick-start snippets to configure the app.</li>
      </ul>
      <h3>Status</h3>
      <p>
        <strong>Disable</strong> stops the gateway from issuing assertions/tokens to the app
        without deleting its configuration; <strong>Delete</strong> permanently removes the app
        and its mappings.
      </p>
    </div>
  ),
};

export const samlConfigHelp: HelpContent = {
  header: <h2>SAML configuration</h2>,
  content: (
    <div>
      <p>Controls how the gateway acts as a SAML IdP for this service provider (SP).</p>
      <h3>Identity</h3>
      <dl>
        <dt><strong>Entity ID</strong></dt>
        <dd>The SP's unique SAML identifier. Must match the SP's metadata exactly.</dd>
        <dt><strong>ACS URL</strong></dt>
        <dd>The SP's Assertion Consumer Service — where the gateway POSTs the SAML response.</dd>
        <dt><strong>NameID format / source</strong></dt>
        <dd>
          The format of the subject identifier (email, persistent, transient, unspecified) and
          which Cognito attribute supplies it (e.g. <code>email</code>, <code>sub</code>).
        </dd>
      </dl>
      <h3>Signing &amp; encryption</h3>
      <dl>
        <dt><strong>Sign Response / Sign Assertion</strong></dt>
        <dd>
          Whether the gateway signs the SAML response, the assertion, or both, with the
          gateway signing certificate (see the Certificates page). Most SPs require at least
          one; signing the assertion is the common choice.
        </dd>
        <dt><strong>Encrypt Assertion</strong></dt>
        <dd>Encrypts the assertion to the SP's public key (when the SP supplies one).</dd>
      </dl>
      <h3>IdP-initiated SSO</h3>
      <p>
        <strong>Allow IdP-initiated SSO</strong> permits unsolicited assertions to this SP via
        the gateway's <code>/saml/idp-initiate</code> endpoint (used by an app launcher).
        Disabled by default — it is an opt-in because IdP-initiated SSO can be an abuse vector.
      </p>
      <h3>Sessions</h3>
      <dl>
        <dt><strong>Session duration</strong></dt>
        <dd>How long the issued assertion's session is valid (seconds).</dd>
        <dt><strong>Clock skew</strong></dt>
        <dd>Tolerance for time differences between the gateway and SP when validating timestamps.</dd>
        <dt><strong>SLO URL</strong></dt>
        <dd>The SP's Single Logout endpoint (optional).</dd>
      </dl>
    </div>
  ),
};

export const oidcConfigHelp: HelpContent = {
  header: <h2>OIDC configuration</h2>,
  content: (
    <div>
      <p>Controls how the gateway acts as an OpenID Provider for this relying party (RP).</p>
      <h3>Endpoints &amp; grants</h3>
      <dl>
        <dt><strong>Redirect URIs</strong></dt>
        <dd>
          Exact-match allowlist of where the gateway may return the authorization code. A
          request whose <code>redirect_uri</code> is not listed is rejected.
        </dd>
        <dt><strong>Post-logout redirect URIs</strong></dt>
        <dd>Allowed destinations after end-session/logout.</dd>
        <dt><strong>Grant types / Response types</strong></dt>
        <dd>The OAuth 2.0 flows the client may use. Authorization Code + <code>code</code> is the standard, secure choice.</dd>
        <dt><strong>Scopes</strong></dt>
        <dd>Scopes the client may request (e.g. <code>openid</code>, <code>email</code>, <code>profile</code>).</dd>
      </dl>
      <h3>Client authentication</h3>
      <dl>
        <dt><strong>Token endpoint auth method</strong></dt>
        <dd>
          <code>none</code> for public clients (SPAs/native, with PKCE), or
          <code> client_secret_post</code>/<code>client_secret_basic</code> for confidential
          clients. Use <strong>Regenerate Secret</strong> to rotate a confidential client's secret.
        </dd>
      </dl>
      <h3>Token lifetimes</h3>
      <p>
        <strong>ID token</strong> and <strong>Access token</strong> lifetimes (seconds) control
        how long issued tokens remain valid before the client must refresh.
      </p>
    </div>
  ),
};

export const customLoginHelp: HelpContent = {
  header: <h2>Custom login page</h2>,
  content: (
    <div>
      <p>
        By default, unauthenticated users are sent to the Cognito Hosted UI. A custom login URL
        <strong> replaces</strong> that for this application: the gateway redirects the user to
        your page, which authenticates them and posts a Cognito ID token back to the gateway's
        session-establish endpoint to resume SSO.
      </p>
      <h3>Fields</h3>
      <dl>
        <dt><strong>Custom login URL</strong></dt>
        <dd>
          The https URL of your login page. When set, it is used instead of the Hosted UI for
          this app. Must be covered by the trusted-redirect allowlist below.
        </dd>
        <dt><strong>Trusted login redirect URIs</strong></dt>
        <dd>
          Allowlist of permitted login-page URLs (https). The custom login URL must match one
          of these — this prevents an accidental open redirect to an untrusted host.
        </dd>
      </dl>
      <h3>Flow</h3>
      <p>
        Gateway redirects to <code>customLoginUrl?return_to=&lt;…/login/complete&gt;&amp;state=&lt;flowId&gt;</code>
        → your page signs the user in → it POSTs the ID token + <code>state</code> back → the
        gateway verifies the token (its audience must match this app's identity source) and
        resumes the SAML/OIDC flow.
      </p>
    </div>
  ),
};

export const integrationHelp: HelpContent = {
  header: <h2>Integration</h2>,
  content: (
    <div>
      <p>
        The values an administrator hands to the application owner to trust this gateway.
        Everything here is read-only and derived from the app + gateway configuration.
      </p>
      <h3>Connection details</h3>
      <ul>
        <li><strong>IdP Metadata URL</strong> — point a SAML SP here to import IdP metadata automatically.</li>
        <li><strong>App-Specific Metadata URL</strong> — metadata scoped to this app (includes its released attributes).</li>
        <li><strong>Entity ID / SSO URL / SLO URL</strong> (SAML) or <strong>Discovery / Authorization / Token</strong> endpoints (OIDC).</li>
      </ul>
      <h3>Certificate</h3>
      <p>
        The SHA-256 fingerprint of the gateway's <em>global</em> signing certificate. Every
        application is signed with this single IdP certificate (standard SAML practice). Manage
        or rotate it on the <strong>Certificates</strong> page — the per-app view is read-only and
        exists only so the app owner can pin/trust it.
      </p>
      <h3>Quick start &amp; Test</h3>
      <p>
        Copy/paste configuration snippets for common SP/RP platforms, and a <strong>Test</strong>
        action that initiates a live SSO so you can verify the integration end to end.
      </p>
    </div>
  ),
};
