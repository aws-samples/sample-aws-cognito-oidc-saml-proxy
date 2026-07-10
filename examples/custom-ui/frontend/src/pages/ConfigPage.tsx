import { getConfig } from '../config';
import HelpDoc from '../components/HelpDoc';

export default function ConfigPage() {
  const cfg = getConfig();
  const origin = window.location.origin;
  const loginUrl = `${origin}/login`;
  const tenant = cfg.gatewayTenant || '<tenant>';
  const gateway = cfg.gatewayBaseUrl || 'https://<gateway-host>';

  return (
    <>
      <h2>Configuration</h2>
      <p className="muted">
        Everything this demo needs, and how to wire it into the Federation Gateway. These
        values are served at runtime from <code className="inline">/config.json</code> (populated by Terraform),
        so you reconfigure by changing Terraform variables — no rebuild.
      </p>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>This deployment</h3>
        <div className="kv">
          <Row k="App origin" v={origin} />
          <Row k="Cognito User Pool ID" v={cfg.userPoolId || '(not set)'} />
          <Row k="Cognito App Client ID" v={cfg.clientId || '(not set)'} />
          <Row k="Region" v={cfg.region || '(not set)'} />
          <Row k="Gateway base URL" v={cfg.gatewayBaseUrl || '(not set)'} />
          <Row k="Gateway tenant" v={cfg.gatewayTenant || '(not set)'} />
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>1. Cognito App Client requirements</h3>
        <div className="kv">
          <Row k="Client type" v="Public (no client secret)" />
          <Row k="ALLOW_USER_SRP_AUTH" v="Required — SRP sign-in" />
          <Row k="ALLOW_REFRESH_TOKEN_AUTH" v="Required — seamless token refresh" />
          <Row k="Callback / Logout URLs" v="Not required for this app (direct SRP, not Hosted UI)" />
        </div>
        <p className="muted" style={{ marginTop: 12 }}>
          The Federation Gateway's SPA app client already enables both auth flows and has no
          secret, so it can be reused. Otherwise create a dedicated public client.
        </p>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>2. User pool requirement (for self sign-up)</h3>
        <div className="alert warn">
          Self-registration requires <code className="inline">allow_admin_create_user_only = false</code> on the
          user pool. The gateway's pool ships with admin-create-<em>only</em> enabled, which blocks
          the Register page. Use a pool with self sign-up enabled, or have an admin create users
          (they will hit the “new password required” flow on first login).
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>3. Use as the Federation Gateway custom login page</h3>
        <p className="muted">
          This app authenticates against the same pool the gateway uses as an identity source,
          so it can serve as a per-application custom login page (REPLACE mode).
        </p>
        <h4 style={{ color: 'var(--accent)' }}>On the gateway application config</h4>
        <div className="kv">
          <Row k="customLoginUrl" v={loginUrl} />
          <Row k="trustedLoginRedirectUris" v={`${origin}/`} />
        </div>
        <h4 style={{ color: 'var(--accent)' }}>Session-establish endpoints (where this app posts the ID token)</h4>
        <pre>{`SAML: POST ${gateway}/t/${tenant}/saml/login/complete
OIDC: POST ${gateway}/t/${tenant}/oidc/login/complete

Body (one of):
  Authorization: Bearer <Cognito ID token>
  -- or form field --
  id_token=<Cognito ID token>
Plus: state=<flowId from the gateway redirect>`}</pre>
        <p className="muted">
          The gateway redirects unauthenticated users here with
          <code className="inline">?return_to=&lt;...login/complete&gt;&amp;state=&lt;flowId&gt;</code>; after login, post the
          ID token (from <code className="inline">localStorage</code> / <code className="inline">getIdToken()</code>) plus the echoed
          <code className="inline">state</code> to <code className="inline">return_to</code> to resume SSO.
        </p>
      </div>

      <HelpDoc title="How configuration reaches the app">
        <pre>{`Terraform variables (cognito_user_pool_id, cognito_client_id, ...)
  -> Lambda environment variables
     -> GET /config.json  (served by the Go Lambda from its env)
        -> SPA loadConfig() at startup
           -> CognitoUserPool({ UserPoolId, ClientId })`}</pre>
        <p>For local <code className="inline">npm run dev</code>, the same values come from
        <code className="inline">.env.local</code> (<code className="inline">VITE_*</code>) instead of <code className="inline">/config.json</code>.</p>
      </HelpDoc>
    </>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <>
      <div className="k">{k}</div>
      <div className="v">{v}</div>
    </>
  );
}
