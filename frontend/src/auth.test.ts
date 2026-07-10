import { describe, it, expect, beforeEach, vi } from 'vitest';

// aws-amplify modules run real network/config code at import; stub them so the
// module-level Amplify.configure() in auth.ts is inert and fetchAuthSession is
// controllable per test.
const fetchAuthSession = vi.fn();
vi.mock('aws-amplify', () => ({ Amplify: { configure: vi.fn() } }));
vi.mock('aws-amplify/auth', () => ({
  signInWithRedirect: vi.fn(),
  signOut: vi.fn(),
  getCurrentUser: vi.fn(),
  fetchAuthSession: (...args: unknown[]) => fetchAuthSession(...args),
}));
vi.mock('aws-amplify/auth/cognito', () => ({
  cognitoUserPoolsTokenProvider: { setKeyValueStorage: vi.fn() },
}));
vi.mock('aws-amplify/utils', () => ({ sharedInMemoryStorage: {} }));

// Control the operator-selected tenant.
const getActiveTenant = vi.fn<() => string | null>();
vi.mock('./tenant', () => ({
  getActiveTenant: () => getActiveTenant(),
  setActiveTenant: vi.fn(),
  DEFAULT_TENANT_SLUG: 'default',
}));

/** Build a fake Amplify session. token===null → no session. */
function session(token: string | null, groups: string[] = []) {
  if (!token) return { tokens: undefined };
  return {
    tokens: {
      idToken: {
        toString: () => token,
        payload: { 'cognito:groups': groups },
      },
    },
  };
}

async function loadAuth() {
  // auth.ts throws at import if VITE_COGNITO_* are absent (fail closed). Provide
  // them, then re-import fresh so env + mocks apply.
  vi.stubEnv('VITE_COGNITO_USER_POOL_ID', 'eu-north-1_test');
  vi.stubEnv('VITE_COGNITO_CLIENT_ID', 'test-client');
  vi.stubEnv('VITE_COGNITO_DOMAIN', 'auth.example.com');
  vi.stubEnv('VITE_TOKEN_STORAGE', 'memory'); // skip the localStorage read path
  return import('./auth');
}

describe('authFetch (fail-closed)', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.resetModules();
    vi.unstubAllEnvs();
    fetchAuthSession.mockReset();
    getActiveTenant.mockReset();
    fetchMock.mockReset();
    fetchMock.mockResolvedValue(new Response('{}', { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
  });

  it('fails closed and does not send an unauthenticated request when there is no token', async () => {
    fetchAuthSession.mockResolvedValue(session(null));
    getActiveTenant.mockReturnValue(null);
    const { authFetch, AuthRequiredError } = await loadAuth();

    await expect(authFetch('/api/v1/tenants')).rejects.toBeInstanceOf(AuthRequiredError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('attaches the bearer token when authenticated', async () => {
    fetchAuthSession.mockResolvedValue(session('jwt-abc', []));
    getActiveTenant.mockReturnValue(null);
    const { authFetch } = await loadAuth();

    await authFetch('/api/v1/tenants');
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Headers;
    expect(headers.get('Authorization')).toBe('Bearer jwt-abc');
  });

  it('does NOT send X-Tenant-Id for a non-operator even when a tenant is selected', async () => {
    fetchAuthSession.mockResolvedValue(session('jwt-abc', ['Admins']));
    getActiveTenant.mockReturnValue('other-tenant');
    const { authFetch } = await loadAuth();

    await authFetch('/api/v1/tenants');
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Headers;
    expect(headers.has('X-Tenant-Id')).toBe(false);
  });

  it('sends X-Tenant-Id only for a global operator with a selected tenant', async () => {
    fetchAuthSession.mockResolvedValue(session('jwt-abc', ['GlobalOperators']));
    getActiveTenant.mockReturnValue('other-tenant');
    const { authFetch } = await loadAuth();

    await authFetch('/api/v1/tenants');
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Headers;
    expect(headers.get('X-Tenant-Id')).toBe('other-tenant');
  });

  it('does NOT send X-Tenant-Id for a global operator when no tenant is selected', async () => {
    fetchAuthSession.mockResolvedValue(session('jwt-abc', ['GlobalOperators']));
    getActiveTenant.mockReturnValue(null);
    const { authFetch } = await loadAuth();

    await authFetch('/api/v1/tenants');
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Headers;
    expect(headers.has('X-Tenant-Id')).toBe(false);
  });
});
