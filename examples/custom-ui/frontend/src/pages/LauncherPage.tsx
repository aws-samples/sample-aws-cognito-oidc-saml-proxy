import { useState } from 'react';
import { getConfig, type LaunchApp } from '../config';
import { getIdToken } from '../cognito';
import { launchSamlApp } from '../gateway';
import HelpDoc from '../components/HelpDoc';

export default function LauncherPage() {
  const cfg = getConfig();
  const apps = cfg.apps ?? [];
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const launch = async (app: LaunchApp) => {
    setError(null);
    setBusy(app.label);
    try {
      if (app.protocol === 'saml') {
        if (!app.samlEntityId) throw new Error('app is missing samlEntityId');
        const idToken = await getIdToken(); // refreshes if needed
        if (!idToken) throw new Error('no valid session — please sign in again');
        launchSamlApp(app.samlEntityId, idToken, app.relayState); // navigates away
        return;
      }
      // OIDC (or generic): there is no IdP-initiated flow; navigate to the
      // configured post-auth redirect URL (e.g. the RP's login-start URL).
      if (!app.redirectUrl) throw new Error('app is missing redirectUrl');
      window.location.href = app.redirectUrl;
    } catch (err) {
      setBusy(null);
      setError(err instanceof Error ? err.message : 'Launch failed');
    }
  };

  return (
    <>
      <h2>App Launcher</h2>
      <p className="muted">
        Start SSO into a registered application from here (IdP-initiated). You are already
        signed in; the gateway will not prompt again.
      </p>
      {error && <div className="alert err">{error}</div>}

      {apps.length === 0 ? (
        <div className="card">
          <div className="alert warn">
            No apps configured. Set the <code className="inline">apps_json</code> Terraform variable
            (served at <code className="inline">/config.json</code>) to populate this launcher. See the
            help below.
          </div>
        </div>
      ) : (
        <div className="card">
          <div className="kv" style={{ gridTemplateColumns: '1fr auto' }}>
            {apps.map((app) => (
              <Entry key={app.label} app={app} busy={busy === app.label} onLaunch={() => launch(app)} />
            ))}
          </div>
        </div>
      )}

      <HelpDoc>
        <h4>SAML — IdP-initiated</h4>
        <p>Clicking a SAML app does a top-level form POST of your Cognito ID token to the
        gateway's IdP-initiated endpoint:</p>
        <pre>{`POST <gateway>/t/<tenant>/saml/idp-initiate
  id_token=<Cognito ID token>
  entityId=<SP SAML entity id>
  relayState=<optional deep link>`}</pre>
        <p>The gateway verifies the token (its <code className="inline">aud</code> must match the app's bound
        identity source), mints an <strong>unsolicited SAML assertion</strong>, and auto-POSTs it to
        the SP's ACS URL — no prior SAMLRequest needed.</p>

        <h4>OIDC — post-auth redirect</h4>
        <p>OIDC has no IdP-initiated flow. Instead, the launcher navigates the browser to a
        configured <code className="inline">redirectUrl</code> (typically the relying party's login-start URL).
        Because you already have a session here, the resulting SP-initiated flow completes
        without another prompt.</p>

        <h4>Configuration (apps_json)</h4>
        <pre>{`[
  { "label": "ALB SAML App", "protocol": "saml",
    "samlEntityId": "urn:amazon:cognito:sp:us-east-1_XXXX",
    "relayState": "https://app.example.com/home" },
  { "label": "OIDC Web App", "protocol": "oidc",
    "redirectUrl": "https://rp.example.com/login" }
]`}</pre>
      </HelpDoc>
    </>
  );
}

function Entry({ app, busy, onLaunch }: { app: LaunchApp; busy: boolean; onLaunch: () => void }) {
  return (
    <>
      <div>
        <strong>{app.label}</strong>{' '}
        <span className="pill">{app.protocol.toUpperCase()}</span>
        <div className="muted" style={{ fontSize: 12, wordBreak: 'break-all' }}>
          {app.protocol === 'saml' ? app.samlEntityId : app.redirectUrl}
        </div>
      </div>
      <div style={{ alignSelf: 'center' }}>
        <button onClick={onLaunch} disabled={busy}>{busy ? 'Launching…' : 'Launch'}</button>
      </div>
    </>
  );
}
