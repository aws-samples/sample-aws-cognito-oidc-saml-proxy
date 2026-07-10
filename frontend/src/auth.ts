import { Amplify } from 'aws-amplify';
import { signInWithRedirect, signOut, getCurrentUser, fetchAuthSession } from 'aws-amplify/auth';
import { cognitoUserPoolsTokenProvider } from 'aws-amplify/auth/cognito';
import { sharedInMemoryStorage } from 'aws-amplify/utils';
import { getActiveTenant } from './tenant';

// Cognito configuration — MUST be injected at build time via VITE_* environment variables.
// The deploy pipeline reads these from Terraform outputs. See Makefile `frontend-build` target.
const userPoolId = import.meta.env.VITE_COGNITO_USER_POOL_ID;
const userPoolClientId = import.meta.env.VITE_COGNITO_CLIENT_ID;
const cognitoDomain = import.meta.env.VITE_COGNITO_DOMAIN;

if (!userPoolId || !userPoolClientId || !cognitoDomain) {
  throw new Error(
    'Cognito configuration missing. Build with: VITE_COGNITO_USER_POOL_ID, VITE_COGNITO_CLIENT_ID, VITE_COGNITO_DOMAIN'
  );
}

// Derive redirect URLs from current origin (works for both localhost and CloudFront)
const origin = window.location.origin;

// Token storage mode. Default 'local': Amplify persists Cognito tokens in
// localStorage, so a session survives page reloads. Set VITE_TOKEN_STORAGE=memory
// for in-memory-only tokens — they are never written to disk, which removes the
// at-rest XSS exfiltration surface (an injected script cannot read a token out
// of localStorage that was never written). Trade-off: tokens are cleared on a
// full page reload, after which the user is re-authenticated via the Cognito
// Hosted UI session (silent if that session is still valid).
const tokenStorageMode = String(
  import.meta.env.VITE_TOKEN_STORAGE ?? 'local'
).toLowerCase();
const useInMemoryTokens = tokenStorageMode === 'memory';

Amplify.configure({
  Auth: {
    Cognito: {
      userPoolId,
      userPoolClientId,
      loginWith: {
        oauth: {
          domain: cognitoDomain,
          scopes: ['openid', 'email', 'profile'],
          redirectSignIn: [`${origin}/callback`],
          redirectSignOut: [`${origin}/`],
          responseType: 'code',
        },
      },
    },
  },
});

// Apply the in-memory token store after configure(). Amplify.configure installs
// the default (localStorage) store on the token provider, so this override must
// run afterward. No-op in the default 'local' mode.
if (useInMemoryTokens) {
  cognitoUserPoolsTokenProvider.setKeyValueStorage(sharedInMemoryStorage);
}

export async function login() {
  await signInWithRedirect();
}

export async function logout() {
  await signOut();
}

export async function getUser() {
  try {
    return await getCurrentUser();
  } catch {
    return null;
  }
}

export async function getAccessToken(): Promise<string | null> {
  try {
    const session = await fetchAuthSession();
    return session.tokens?.accessToken?.toString() ?? null;
  } catch {
    return null;
  }
}

export async function getIdToken(): Promise<string | null> {
  // In local mode, try localStorage first (immediate, no async delay).
  // Amplify stores tokens under a predictable key pattern. Skipped in
  // in-memory mode, where nothing is ever written to localStorage.
  if (!useInMemoryTokens) {
    try {
      const lastUser = localStorage.getItem(
        `CognitoIdentityServiceProvider.${userPoolClientId}.LastAuthUser`
      );
      if (lastUser) {
        const token = localStorage.getItem(
          `CognitoIdentityServiceProvider.${userPoolClientId}.${lastUser}.idToken`
        );
        if (token) return token;
      }
    } catch { /* fall through */ }
  }

  // Fallback (and the only path in in-memory mode): Amplify session API, which
  // reads from whichever token store is configured.
  try {
    const session = await fetchAuthSession();
    return session.tokens?.idToken?.toString() ?? null;
  } catch {
    return null;
  }
}

// GLOBAL_OPERATOR_GROUP mirrors the backend's GlobalOperatorGroup
// (internal/middleware/tenant.go): the ONLY Cognito group whose members may
// scope a request to a tenant other than the one bound to their token. Kept in
// sync with the server, which remains authoritative.
const GLOBAL_OPERATOR_GROUP = 'GlobalOperators';

// AuthRequiredError is thrown by authFetch when there is no usable session, so
// callers never mistake a silently-unauthenticated request for a real response.
export class AuthRequiredError extends Error {
  constructor() {
    super('authentication required');
    this.name = 'AuthRequiredError';
  }
}

/**
 * isGlobalOperator reports whether the current session holds the cross-tenant
 * global-operator role, read from the ID token's cognito:groups claim. This is
 * a client-side mirror of the server's authorization gate, used only to
 * decide whether to attach a tenant-override header — the server, not this
 * check, is authoritative and rejects an unauthorized override with 403.
 */
export async function isGlobalOperator(): Promise<boolean> {
  try {
    const session = await fetchAuthSession();
    const groups = session.tokens?.idToken?.payload?.['cognito:groups'];
    return Array.isArray(groups) && groups.includes(GLOBAL_OPERATOR_GROUP);
  } catch {
    return false;
  }
}

/**
 * Authenticated fetch wrapper. Attaches the Cognito ID token as a Bearer token.
 *
 * Fails closed: if there is no usable token the request is NOT sent.
 * Instead we kick off the Cognito re-auth redirect and throw AuthRequiredError,
 * so an expired/absent session can never surface as a silently-unauthenticated
 * request that relies entirely on the server to reject it.
 *
 * Cross-tenant scoping is an explicit, operator-only action. The generic
 * wrapper no longer attaches whatever tenant the client happens to have
 * selected on every data request. The X-Tenant-Id override is sent ONLY when
 * (a) an operator has explicitly selected a non-default tenant via the switcher
 * AND (b) this session actually holds the global-operator role. A per-tenant
 * admin's console therefore never emits a cross-tenant header at all; the
 * server still validates the override and rejects it with 403 for any
 * caller lacking the role.
 */
export async function authFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  const token = await getIdToken();
  if (!token) {
    // No session — do not send an unauthenticated request. Trigger re-auth and
    // surface a typed error to the caller.
    void login();
    throw new AuthRequiredError();
  }

  const headers = new Headers(init?.headers);
  headers.set('Authorization', `Bearer ${token}`);

  const activeTenant = getActiveTenant();
  if (activeTenant && (await isGlobalOperator())) {
    headers.set('X-Tenant-Id', activeTenant);
  }
  return fetch(input, { ...init, headers });
}
