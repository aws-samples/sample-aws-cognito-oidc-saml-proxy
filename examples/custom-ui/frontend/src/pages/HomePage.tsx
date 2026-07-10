import { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { getValidSession, decodeJwt, logout, globalLogout } from '../cognito';
import { useAuth } from '../auth-context';
import HelpDoc from '../components/HelpDoc';

interface TokenView {
  idToken: string;
  accessToken: string;
  claims: Record<string, unknown>;
  expSec: number; // id token exp (epoch seconds)
}

export default function HomePage() {
  const navigate = useNavigate();
  const { refresh } = useAuth();
  const [view, setView] = useState<TokenView | null>(null);
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000));
  const [refreshing, setRefreshing] = useState(false);
  const [refreshNote, setRefreshNote] = useState<string | null>(null);

  const load = useCallback(async () => {
    const session = await getValidSession();
    if (!session) {
      setView(null);
      return;
    }
    const idToken = session.getIdToken().getJwtToken();
    const accessToken = session.getAccessToken().getJwtToken();
    const claims = decodeJwt(idToken);
    setView({ idToken, accessToken, claims, expSec: Number(claims.exp ?? 0) });
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Tick the clock so the expiry countdown updates.
  useEffect(() => {
    const t = setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000);
    return () => clearInterval(t);
  }, []);

  const onRefresh = async () => {
    setRefreshing(true);
    setRefreshNote(null);
    const before = view?.idToken;
    await load(); // getValidSession() auto-refreshes if the token is expired
    setRefreshing(false);
    // Compare to show whether a new token was issued.
    const session = await getValidSession();
    const after = session?.getIdToken().getJwtToken();
    setRefreshNote(
      after && after !== before
        ? 'A new ID token was issued (refresh token exchange occurred).'
        : 'Existing token still valid — no refresh was necessary yet.'
    );
  };

  const onLogout = async () => {
    logout();
    await refresh();
    navigate('/login');
  };

  const onGlobalLogout = async () => {
    await globalLogout();
    await refresh();
    navigate('/login');
  };

  if (!view) {
    return <p className="muted">Loading session…</p>;
  }

  const secondsLeft = view.expSec - now;

  return (
    <>
      <h2>Home / Profile</h2>
      <p className="muted">You are signed in. Tokens are stored in this browser's localStorage.</p>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>ID token claims</h3>
        <div className="kv">
          {Object.entries(view.claims).map(([k, v]) => (
            <Row key={k} k={k} v={typeof v === 'object' ? JSON.stringify(v) : String(v)} />
          ))}
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0 }}>Session</h3>
        <div className="row" style={{ marginBottom: 8 }}>
          <span className="pill">
            ID token expires in {secondsLeft > 0 ? `${secondsLeft}s` : 'expired'}
          </span>
        </div>
        {refreshNote && <div className="alert ok">{refreshNote}</div>}
        <div className="row">
          <button className="secondary" onClick={onRefresh} disabled={refreshing}>
            {refreshing ? 'Checking…' : 'Refresh / validate session'}
          </button>
          <button onClick={onLogout}>Log out</button>
          <button className="secondary" onClick={onGlobalLogout}>Global sign-out</button>
        </div>

        <label>ID token (display only)</label>
        <pre>{view.idToken}</pre>
        <label>Access token (display only)</label>
        <pre>{view.accessToken}</pre>
      </div>

      <HelpDoc>
        <h4>Seamless token refresh</h4>
        <p>ID and access tokens are short-lived (often 1 hour). Rather than erroring when they
        expire, every protected call here goes through
        <code className="inline">getValidSession()</code>, which wraps
        <code className="inline">cognitoUser.getSession()</code>. If the cached ID/access token is expired
        but the refresh token is still valid, the SDK silently calls
        <code className="inline">InitiateAuth(REFRESH_TOKEN_AUTH)</code>, stores fresh tokens in localStorage,
        and returns a valid session — no error reaches your UI.</p>
        <pre>{`getValidSession()
  -> cognitoUser.getSession()
     -> id/access expired? AND refresh token valid?
        -> InitiateAuth(REFRESH_TOKEN_AUTH)
           -> new id/access tokens stored
              -> valid session returned`}</pre>

        <h4>Logout</h4>
        <ul>
          <li><strong>Log out</strong> → <code className="inline">cognitoUser.signOut()</code> clears tokens from
          this browser's localStorage only.</li>
          <li><strong>Global sign-out</strong> → <code className="inline">cognitoUser.globalSignOut()</code>
          (<code className="inline">GlobalSignOut</code> API) revokes the refresh token server-side across all
          devices, then clears local tokens. Requires a valid session.</li>
        </ul>

        <h4>Required app client setting</h4>
        <ul>
          <li><code className="inline">ALLOW_REFRESH_TOKEN_AUTH</code> must be enabled for refresh to work.</li>
        </ul>
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
