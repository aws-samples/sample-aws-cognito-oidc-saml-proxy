import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { forgotPassword, confirmForgotPassword } from '../cognito';
import HelpDoc from '../components/HelpDoc';

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [step, setStep] = useState<'request' | 'confirm'>('request');
  const [username, setUsername] = useState('');
  const [code, setCode] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await forgotPassword(username.trim());
      setNotice('If the account exists, a reset code has been emailed.');
      setStep('confirm');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start password reset');
    } finally {
      setBusy(false);
    }
  };

  const onConfirm = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await confirmForgotPassword(username.trim(), code.trim(), newPassword);
      setNotice('Password reset. You can now sign in.');
      setTimeout(() => navigate('/login'), 1200);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not reset password');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h2>Forgot password</h2>
      {error && <div className="alert err">{error}</div>}
      {notice && <div className="alert ok">{notice}</div>}

      {step === 'request' ? (
        <form className="card" onSubmit={onRequest}>
          <label htmlFor="username">Email</label>
          <input id="username" type="email" value={username} onChange={(e) => setUsername(e.target.value)} required />
          <button type="submit" disabled={busy}>{busy ? 'Sending…' : 'Send reset code'}</button>
        </form>
      ) : (
        <form className="card" onSubmit={onConfirm}>
          <label htmlFor="code">Reset code (emailed)</label>
          <input id="code" value={code} onChange={(e) => setCode(e.target.value)} inputMode="numeric" required />
          <label htmlFor="newPassword">New password</label>
          <input id="newPassword" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password" required />
          <button type="submit" disabled={busy}>{busy ? 'Resetting…' : 'Set new password'}</button>
        </form>
      )}

      <HelpDoc>
        <h4>What this page does</h4>
        <p>Resets the password for a user who cannot sign in. Cognito emails a verification
        code; the user supplies it together with a new password. No prior session needed.</p>

        <h4>Cognito API calls</h4>
        <ul>
          <li><code className="inline">cognitoUser.forgotPassword(callbacks)</code> →
          <code className="inline">ForgotPassword</code> API (emails the code).</li>
          <li><code className="inline">cognitoUser.confirmPassword(code, newPassword, callbacks)</code> →
          <code className="inline">ConfirmForgotPassword</code> API.</li>
        </ul>

        <h4>Flow</h4>
        <pre>{`Step 1: forgotPassword(username) -> code emailed
Step 2: confirmPassword(code, newPassword)
  -> password updated -> /login`}</pre>

        <h4>Note</h4>
        <ul>
          <li>This is the <strong>unauthenticated</strong> reset flow. To change a password while
          signed in, use the Change password page.</li>
        </ul>
      </HelpDoc>
    </>
  );
}
