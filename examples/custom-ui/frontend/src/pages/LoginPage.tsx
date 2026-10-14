import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { login, completeNewPassword } from '../cognito';
import { useAuth } from '../auth-context';
import { readHandback, isTrustedReturnTo, postTokenToGateway, isTrustedRedirect } from '../gateway';
import { getConfig } from '../config';
import { signInWithPasskey } from '../webauthn';
import HelpDoc from '../components/HelpDoc';

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { refresh } = useAuth();
  const handback = readHandback(location.search);
  const redirectUrl = new URLSearchParams(location.search).get('redirect_url');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [needNewPassword, setNeedNewPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const cfg = getConfig();
  const socialIdps = cfg.socialIdps ?? [];
  const showSocial = !!cfg.cognitoDomain && socialIdps.length > 0;
  const webAuthnSupported =
    typeof window !== 'undefined' && !!window.PublicKeyCredential;
  const passkeyEnabled = cfg.passkeysEnabled === true && webAuthnSupported;
  const showPasskey = cfg.passkeysEnabled === true;

  // After a successful sign-in: (1) hand the ID token back to the gateway
  // (REPLACE-mode custom login), or (2) follow a supplied post-auth redirect_url
  // (validated against the gateway / configured apps), or (3) go to Home.
  const finish = (idToken: string) => {
    if (handback) {
      if (!isTrustedReturnTo(handback.returnTo)) {
        setError('return_to is not the configured gateway origin; refusing to send the token.');
        return;
      }
      postTokenToGateway(handback, idToken); // navigates the browser to the gateway
      return;
    }
    if (redirectUrl) {
      if (!isTrustedRedirect(redirectUrl)) {
        setError('redirect_url is not an allowed destination; refusing to redirect.');
        return;
      }
      window.location.href = redirectUrl;
      return;
    }
    void refresh();
    navigate('/');
  };

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const result = await login(email.trim(), password);
      if (result.status === 'newPasswordRequired') {
        setNeedNewPassword(true);
        return;
      }
      finish(result.session.getIdToken().getJwtToken());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setBusy(false);
    }
  };

  const onSetNewPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const session = await completeNewPassword(newPwd);
      finish(session.getIdToken().getJwtToken());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to set new password');
    } finally {
      setBusy(false);
    }
  };

  // Social sign-in: a REAL top-level redirect to the Cognito Hosted-UI
  // /oauth2/authorize endpoint for the chosen identity provider. The gateway /
  // app client must have the provider enabled and {origin}/login registered as a
  // callback URL. Nothing is faked — the browser leaves this SPA entirely.
  const onSocial = (idp: string) => {
    if (!cfg.cognitoDomain) return;
    const origin = window.location.origin;
    const params = new URLSearchParams({
      identity_provider: idp,
      response_type: 'code',
      client_id: cfg.clientId,
      redirect_uri: `${origin}/login`,
      scope: 'openid email profile',
    });
    window.location.href = `https://${cfg.cognitoDomain}/oauth2/authorize?${params.toString()}`;
  };

  // Passkey sign-in: runs the REAL Cognito USER_AUTH -> WEB_AUTHN flow and routes
  // the resulting ID token through the SAME finish() path as password sign-in.
  const onPasskey = async () => {
    setError(null);
    setBusy(true);
    try {
      const idToken = await signInWithPasskey(email.trim());
      finish(idToken);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Passkey sign-in failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-split">
      <div className="login-left">
        <div className="login-card">
          <div className="login-brand">
            <svg
              className="mark"
              width="34"
              height="34"
              viewBox="0 0 24 24"
              fill="currentColor"
              aria-hidden="true"
            >
              <path d="M6.5 19a4.5 4.5 0 0 1-.5-8.97A6 6 0 0 1 17.7 9.2a3.8 3.8 0 0 1-.2 7.6c-.03 0-.07 0-.1-.01V17H6.5v2Z" />
            </svg>
            <span className="name">Nimbus ID</span>
          </div>

          {!needNewPassword ? (
            <>
              <h1 className="login-heading">Welcome back</h1>
              <p className="login-sub">Sign in to continue to your account.</p>

              {handback && (
                <div className="login-handback" role="status">
                  Signing in here will return you to the Federation Gateway to complete SSO.
                </div>
              )}
              {error && <div className="alert err" role="alert">{error}</div>}

              <form onSubmit={onSubmit}>
                <div className="login-field">
                  <label htmlFor="email">Email</label>
                  <div className="login-input-wrap">
                    <span className="field-icon" aria-hidden="true">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="3" y="5" width="18" height="14" rx="2" />
                        <path d="m3 7 9 6 9-6" />
                      </svg>
                    </span>
                    <input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoComplete="username"
                      placeholder="you@example.com"
                      required
                    />
                  </div>
                </div>

                <div className="login-field">
                  <label htmlFor="password">Password</label>
                  <div className="login-input-wrap">
                    <span className="field-icon" aria-hidden="true">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="4" y="11" width="16" height="9" rx="2" />
                        <path d="M8 11V8a4 4 0 0 1 8 0v3" />
                      </svg>
                    </span>
                    <input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                      placeholder="••••••••"
                      required
                    />
                  </div>
                </div>

                <div className="login-row">
                  <label className="login-remember" htmlFor="remember">
                    <input id="remember" type="checkbox" />
                    Remember me
                  </label>
                  <Link to="/forgot-password">Forgot password?</Link>
                </div>

                <div className="login-actions">
                  <button type="submit" className="btn-gradient" disabled={busy}>
                    {busy ? 'Signing in…' : 'Login'}
                  </button>
                  <Link to="/register" className="btn-outline">Create account</Link>
                </div>
              </form>

              {showSocial && (
                <>
                  <div className="login-divider">or</div>
                  <div className="login-social">
                    {socialIdps.map((s) => (
                      <button
                        key={s.idp}
                        type="button"
                        className="btn-social"
                        style={{ ['--social-color' as string]: s.color ?? '' }}
                        onClick={() => onSocial(s.idp)}
                        disabled={busy}
                      >
                        <span className="dot" aria-hidden="true" />
                        Continue with {s.label}
                      </button>
                    ))}
                  </div>
                </>
              )}

              {showPasskey && (
                <>
                  <button
                    type="button"
                    className="btn-passkey"
                    onClick={onPasskey}
                    disabled={!passkeyEnabled || busy}
                    aria-describedby={!passkeyEnabled ? 'passkey-help' : undefined}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                      <circle cx="9" cy="9" r="4" />
                      <path d="M14.5 11.5 21 18v3h-3l-1-1h-2v-2h-2l1.5-1.5" />
                    </svg>
                    Sign in with a passkey
                  </button>
                  {!passkeyEnabled && (
                    <p id="passkey-help" className="login-help-text">
                      Passkeys aren’t available in this browser. Use your email and password instead.
                    </p>
                  )}
                </>
              )}

              <p className="login-legal">
                By continuing you agree to the <Link to="/config">Terms</Link> and{' '}
                <Link to="/config">Privacy Policy</Link>.
              </p>
            </>
          ) : (
            <>
              <h1 className="login-heading">Set a new password</h1>
              {error && <div className="alert err" role="alert">{error}</div>}
              <form onSubmit={onSetNewPassword}>
                <div className="alert warn">
                  This account requires a new password (typically an admin-created user signing
                  in for the first time). Set a permanent password to continue.
                </div>
                <div className="login-field">
                  <label htmlFor="newPwd">New password</label>
                  <input
                    id="newPwd"
                    type="password"
                    value={newPwd}
                    onChange={(e) => setNewPwd(e.target.value)}
                    autoComplete="new-password"
                    required
                  />
                </div>
                <button type="submit" className="btn-gradient" disabled={busy}>
                  {busy ? 'Saving…' : 'Set password & sign in'}
                </button>
              </form>
            </>
          )}

          <HelpDoc>
            <h4>What this page does</h4>
            <p>Signs a user in directly against the Cognito user pool using SRP (Secure Remote
            Password). The password is never transmitted in the clear.</p>

            <h4>URL parameters</h4>
            <ul>
              <li>None. This is a pure SPA route (<code className="inline">/login</code>). After a successful
              redirect from a relying party, your app may receive a <code className="inline">return_to</code> /
              <code className="inline">state</code> query param — see the Configuration page for the gateway
              custom-login flow.</li>
            </ul>

            <h4>Cognito API calls (via amazon-cognito-identity-js)</h4>
            <ul>
              <li><code className="inline">cognitoUser.authenticateUser(authDetails, callbacks)</code> performs the SRP
              handshake: <code className="inline">InitiateAuth(USER_SRP_AUTH)</code> →
              <code className="inline">RespondToAuthChallenge(PASSWORD_VERIFIER)</code>.</li>
              <li>On success, the SDK stores the ID, Access, and Refresh tokens in
              <code className="inline">localStorage</code> under keys prefixed with
              <code className="inline">CognitoIdentityServiceProvider.&lt;clientId&gt;</code>.</li>
              <li>The <code className="inline">newPasswordRequired</code> callback fires for admin-created users
              or forced resets; we complete it with
              <code className="inline">completeNewPasswordChallenge()</code>.</li>
            </ul>

            <h4>Flow</h4>
            <pre>{`User enters email+password
  -> authenticateUser() (SRP)
     -> InitiateAuth / RespondToAuthChallenge
        -> tokens stored in localStorage
           -> app reads session, redirects to Home`}</pre>

            <h4>Required Cognito app client setting</h4>
            <ul>
              <li><code className="inline">ALLOW_USER_SRP_AUTH</code> must be enabled on the app client.</li>
              <li>Public client (no client secret).</li>
            </ul>
          </HelpDoc>
        </div>
      </div>

      <div className="login-right" aria-hidden="true">
        <span className="circle c1" />
        <span className="circle c2" />
        <span className="circle c3" />
        <div className="scrim">
          <p className="tagline">One identity. Every app.</p>
          <p className="blurb">
            A custom login experience with full access to Cognito OAuth endpoints and
            single sign-on — the pieces managed login leaves on the table.
          </p>
        </div>
      </div>
    </div>
  );
}
