import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { confirmSignUp, resendCode } from '../cognito';
import HelpDoc from '../components/HelpDoc';

export default function ConfirmPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [username, setUsername] = useState(params.get('username') ?? '');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await confirmSignUp(username.trim(), code.trim());
      setNotice('Account confirmed. You can now sign in.');
      setTimeout(() => navigate('/login'), 1200);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Confirmation failed');
    } finally {
      setBusy(false);
    }
  };

  const onResend = async () => {
    setError(null);
    setNotice(null);
    try {
      await resendCode(username.trim());
      setNotice('A new confirmation code has been emailed.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not resend code');
    }
  };

  return (
    <>
      <h2>Confirm sign-up</h2>
      {error && <div className="alert err">{error}</div>}
      {notice && <div className="alert ok">{notice}</div>}

      <form className="card" onSubmit={onConfirm}>
        <label htmlFor="username">Email</label>
        <input id="username" type="email" value={username} onChange={(e) => setUsername(e.target.value)} required />
        <label htmlFor="code">Confirmation code</label>
        <input id="code" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" required />
        <div className="row">
          <button type="submit" disabled={busy}>{busy ? 'Confirming…' : 'Confirm'}</button>
          <button type="button" className="secondary" onClick={onResend}>Resend code</button>
        </div>
      </form>

      <HelpDoc>
        <h4>What this page does</h4>
        <p>Confirms a newly registered (UNCONFIRMED) user with the code Cognito emailed,
        transitioning the account to CONFIRMED so it can sign in.</p>

        <h4>URL parameters</h4>
        <ul>
          <li><code className="inline">username</code> — pre-fills the email; passed from the Register page
          (<code className="inline">/confirm?username=user@example.com</code>).</li>
        </ul>

        <h4>Cognito API calls</h4>
        <ul>
          <li><code className="inline">cognitoUser.confirmRegistration(code, true, cb)</code> →
          <code className="inline">ConfirmSignUp</code> API.</li>
          <li><code className="inline">cognitoUser.resendConfirmationCode(cb)</code> →
          <code className="inline">ResendConfirmationCode</code> API.</li>
        </ul>

        <h4>Flow</h4>
        <pre>{`UNCONFIRMED user + emailed code
  -> confirmRegistration(code)
     -> ConfirmSignUp
        -> CONFIRMED -> /login`}</pre>
      </HelpDoc>
    </>
  );
}
