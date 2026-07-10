import { useState } from 'react';
import { changePassword } from '../cognito';
import HelpDoc from '../components/HelpDoc';

export default function ChangePasswordPage() {
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await changePassword(oldPassword, newPassword);
      setNotice('Password changed successfully.');
      setOldPassword('');
      setNewPassword('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change password');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h2>Change password</h2>
      <p className="muted">Authenticated operation — uses your current valid session.</p>
      {error && <div className="alert err">{error}</div>}
      {notice && <div className="alert ok">{notice}</div>}

      <form className="card" onSubmit={onSubmit}>
        <label htmlFor="old">Current password</label>
        <input id="old" type="password" value={oldPassword} onChange={(e) => setOldPassword(e.target.value)} autoComplete="current-password" required />
        <label htmlFor="new">New password</label>
        <input id="new" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} autoComplete="new-password" required />
        <button type="submit" disabled={busy}>{busy ? 'Changing…' : 'Change password'}</button>
      </form>

      <HelpDoc>
        <h4>What this page does</h4>
        <p>Changes the password for the <strong>currently signed-in</strong> user. Unlike the
        forgot-password flow, this requires a valid session and the current password.</p>

        <h4>Cognito API calls</h4>
        <ul>
          <li><code className="inline">cognitoUser.getSession(cb)</code> first — ensures a valid (refreshed)
          session and supplies the access token.</li>
          <li><code className="inline">cognitoUser.changePassword(oldPassword, newPassword, cb)</code> →
          <code className="inline">ChangePassword</code> API (authorized by the access token).</li>
        </ul>

        <h4>Flow</h4>
        <pre>{`getSession() (refresh if needed)
  -> changePassword(old, new)
     -> ChangePassword API
        -> success (tokens unchanged; password updated)`}</pre>
      </HelpDoc>
    </>
  );
}
