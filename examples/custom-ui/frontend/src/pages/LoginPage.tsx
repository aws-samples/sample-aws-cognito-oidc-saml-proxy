import { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { login, completeNewPassword } from '../cognito';
import { useAuth } from '../auth-context';
import { readHandback, isTrustedReturnTo, postTokenToGateway, isTrustedRedirect } from '../gateway';
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

  return (
    <>
      <h2>Login</h2>
      {handback && (
        <div className="alert ok">
          Signing in here will return you to the Federation Gateway to complete SSO.
        </div>
      )}
      {error && <div className="alert err">{error}</div>}

      {!needNewPassword ? (
        <form className="card" onSubmit={onSubmit}>
          <label htmlFor="email">Email</label>
          <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required />
          <label htmlFor="password">Password</label>
          <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          <div className="row">
            <button type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
            <Link to="/forgot-password">Forgot password?</Link>
            <Link to="/register">Create an account</Link>
          </div>
        </form>
      ) : (
        <form className="card" onSubmit={onSetNewPassword}>
          <div className="alert warn">
            This account requires a new password (typically an admin-created user signing
            in for the first time). Set a permanent password to continue.
          </div>
          <label htmlFor="newPwd">New password</label>
          <input id="newPwd" type="password" value={newPwd} onChange={(e) => setNewPwd(e.target.value)} autoComplete="new-password" required />
          <button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Set password & sign in'}</button>
        </form>
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
    </>
  );
}
