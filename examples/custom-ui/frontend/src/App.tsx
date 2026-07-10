import { Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { type ReactNode } from 'react';
import { AuthProvider, useAuth } from './auth-context';
import Layout from './components/Layout';
import HomePage from './pages/HomePage';
import LoginPage from './pages/LoginPage';
import RegisterPage from './pages/RegisterPage';
import ConfirmPage from './pages/ConfirmPage';
import ForgotPasswordPage from './pages/ForgotPasswordPage';
import ChangePasswordPage from './pages/ChangePasswordPage';
import ConfigPage from './pages/ConfigPage';
import LauncherPage from './pages/LauncherPage';

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { authed } = useAuth();
  const location = useLocation();
  if (authed === null) {
    return <p className="muted">Checking session…</p>;
  }
  if (!authed) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />;
  }
  return <>{children}</>;
}

function Shell() {
  const { authed, username } = useAuth();
  return (
    <Layout authed={!!authed} username={username}>
      <Routes>
        <Route path="/" element={<ProtectedRoute><HomePage /></ProtectedRoute>} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route path="/confirm" element={<ConfirmPage />} />
        <Route path="/forgot-password" element={<ForgotPasswordPage />} />
        <Route
          path="/change-password"
          element={<ProtectedRoute><ChangePasswordPage /></ProtectedRoute>}
        />
        <Route
          path="/apps"
          element={<ProtectedRoute><LauncherPage /></ProtectedRoute>}
        />
        <Route path="/config" element={<ConfigPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Shell />
    </AuthProvider>
  );
}
