import { type ReactNode } from 'react';
import { NavLink } from 'react-router-dom';

interface LayoutProps {
  authed: boolean;
  username: string | null;
  children: ReactNode;
}

const linkClass = ({ isActive }: { isActive: boolean }) => (isActive ? 'active' : '');

export default function Layout({ authed, username, children }: LayoutProps) {
  return (
    <div className="app">
      <nav className="nav">
        <h1>Cognito Custom UI</h1>
        <div className="sub">Educational auth demo</div>

        <NavLink to="/" className={linkClass} end>
          Home / Profile
        </NavLink>

        <div className="group">Unauthenticated</div>
        <NavLink to="/login" className={linkClass}>Login</NavLink>
        <NavLink to="/register" className={linkClass}>Register</NavLink>
        <NavLink to="/confirm" className={linkClass}>Confirm sign-up</NavLink>
        <NavLink to="/forgot-password" className={linkClass}>Forgot password</NavLink>

        <div className="group">Authenticated</div>
        <NavLink to="/apps" className={linkClass}>App launcher</NavLink>
        <NavLink to="/change-password" className={linkClass}>Change password</NavLink>

        <div className="group">Reference</div>
        <NavLink to="/config" className={linkClass}>Configuration</NavLink>

        <hr />
        <div className="muted" style={{ fontSize: 12 }}>
          {authed ? (
            <>Signed in as<br /><strong>{username}</strong></>
          ) : (
            'Not signed in'
          )}
        </div>
      </nav>
      <main className="main">{children}</main>
    </div>
  );
}
