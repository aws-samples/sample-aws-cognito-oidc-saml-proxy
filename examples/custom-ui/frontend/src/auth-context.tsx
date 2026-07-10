import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react';
import { getValidSession, currentUsername } from './cognito';

interface AuthState {
  // null = still checking; true/false = resolved
  authed: boolean | null;
  username: string | null;
  /** Re-checks the current session (call after login/logout). */
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  authed: null,
  username: null,
  refresh: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authed, setAuthed] = useState<boolean | null>(null);
  const [username, setUsername] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const session = await getValidSession();
    setAuthed(!!session);
    setUsername(session ? currentUsername() : null);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <AuthContext.Provider value={{ authed, username, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthState {
  return useContext(AuthContext);
}
