import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { signUp } from '../cognito';
import HelpDoc from '../components/HelpDoc';

export default function RegisterPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [givenName, setGivenName] = useState('');
  const [familyName, setFamilyName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const attributes: Record<string, string> = { email: email.trim() };
      if (givenName) attributes.given_name = givenName;
      if (familyName) attributes.family_name = familyName;
      await signUp(email.trim(), password, attributes);
      // Cognito emails a confirmation code; continue on the confirm page.
      navigate(`/confirm?username=${encodeURIComponent(email.trim())}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h2>Register (self sign-up)</h2>
      {error && <div className="alert err">{error}</div>}

      <form className="card" onSubmit={onSubmit}>
        <label htmlFor="email">Email</label>
        <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <label htmlFor="given">First name (optional)</label>
        <input id="given" value={givenName} onChange={(e) => setGivenName(e.target.value)} />
        <label htmlFor="family">Last name (optional)</label>
        <input id="family" value={familyName} onChange={(e) => setFamilyName(e.target.value)} />
        <label htmlFor="password">Password</label>
        <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
        <button type="submit" disabled={busy}>{busy ? 'Creating…' : 'Create account'}</button>
      </form>

      <HelpDoc>
        <h4>What this page does</h4>
        <p>Creates a new user in the Cognito user pool via self-service sign-up, then
        sends the user to the confirmation page to enter the emailed code.</p>

        <h4>Cognito API calls</h4>
        <ul>
          <li><code className="inline">userPool.signUp(username, password, attributeList, [], cb)</code> →
          Cognito <code className="inline">SignUp</code> API.</li>
          <li>Attributes are passed as <code className="inline">CognitoUserAttribute</code> objects (here:
          <code className="inline">email</code>, optional <code className="inline">given_name</code>/<code className="inline">family_name</code>).</li>
          <li>Cognito emails a confirmation code (because <code className="inline">email</code> is an
          auto-verified attribute).</li>
        </ul>

        <h4>Flow</h4>
        <pre>{`signUp() -> Cognito SignUp
  -> user created (UNCONFIRMED)
  -> Cognito emails a 6-digit code
     -> /confirm?username=<email> (next page)
        -> confirmRegistration(code) -> CONFIRMED`}</pre>

        <div className="alert warn">
          <strong>Pool requirement:</strong> self sign-up must be enabled on the user pool
          (<code className="inline">allow_admin_create_user_only = false</code>). The Federation Gateway's
          pool ships with admin-create-only <em>enabled</em>, which blocks self sign-up — see
          the Configuration page.
        </div>
      </HelpDoc>
    </>
  );
}
