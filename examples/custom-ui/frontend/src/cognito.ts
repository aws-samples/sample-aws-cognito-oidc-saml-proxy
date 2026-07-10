// Thin promise-based wrapper around amazon-cognito-identity-js.
//
// This library talks DIRECTLY to the Cognito user pool using a PUBLIC app client
// (no client secret). It performs SRP for sign-in (the password is never sent in
// the clear), persists the resulting ID/Access/Refresh tokens in localStorage,
// and transparently refreshes expired ID/Access tokens via getSession().
//
// EDUCATIONAL NOTE: storing tokens in localStorage is convenient but is exposed
// to XSS. A production app should weigh in-memory storage or a backend-for-
// frontend (HttpOnly cookies). This demo uses localStorage for clarity.

import {
  CognitoUserPool,
  CognitoUser,
  AuthenticationDetails,
  CognitoUserAttribute,
  type CognitoUserSession,
  type ISignUpResult,
} from 'amazon-cognito-identity-js';
import { getConfig } from './config';

let pool: CognitoUserPool | null = null;

/** Lazily builds the CognitoUserPool from runtime config. */
export function getUserPool(): CognitoUserPool {
  if (!pool) {
    const cfg = getConfig();
    pool = new CognitoUserPool({
      UserPoolId: cfg.userPoolId,
      ClientId: cfg.clientId,
      // Storage defaults to window.localStorage, which is what we want for the demo.
    });
  }
  return pool;
}

function makeUser(username: string): CognitoUser {
  return new CognitoUser({ Username: username, Pool: getUserPool() });
}

// ---------------------------------------------------------------------------
// Self-registration (SignUp + ConfirmSignUp)
// ---------------------------------------------------------------------------

/** Calls the Cognito SignUp API. `attributes` are standard/custom user attributes. */
export function signUp(
  username: string,
  password: string,
  attributes: Record<string, string>
): Promise<ISignUpResult> {
  const attrList = Object.entries(attributes).map(
    ([Name, Value]) => new CognitoUserAttribute({ Name, Value })
  );
  return new Promise((resolve, reject) => {
    getUserPool().signUp(username, password, attrList, [], (err, result) => {
      if (err || !result) {
        reject(err ?? new Error('signUp returned no result'));
        return;
      }
      resolve(result);
    });
  });
}

/** Confirms a self-registered user with the emailed confirmation code. */
export function confirmSignUp(username: string, code: string): Promise<void> {
  return new Promise((resolve, reject) => {
    makeUser(username).confirmRegistration(code, true, (err) => {
      err ? reject(err) : resolve();
    });
  });
}

/** Resends the sign-up confirmation code. */
export function resendCode(username: string): Promise<void> {
  return new Promise((resolve, reject) => {
    makeUser(username).resendConfirmationCode((err) => {
      err ? reject(err) : resolve();
    });
  });
}

// ---------------------------------------------------------------------------
// Sign-in (SRP)
// ---------------------------------------------------------------------------

export type LoginResult =
  | { status: 'success'; session: CognitoUserSession }
  | { status: 'newPasswordRequired' };

// Holds state for an in-progress NEW_PASSWORD_REQUIRED challenge.
let pendingNewPassword: {
  user: CognitoUser;
  requiredAttributes: string[];
} | null = null;

/** Authenticates with username + password using SRP. */
export function login(username: string, password: string): Promise<LoginResult> {
  const user = makeUser(username);
  const authDetails = new AuthenticationDetails({
    Username: username,
    Password: password,
  });
  return new Promise((resolve, reject) => {
    user.authenticateUser(authDetails, {
      onSuccess: (session) => resolve({ status: 'success', session }),
      onFailure: (err) => reject(err),
      newPasswordRequired: (userAttributes) => {
        // Admin-created users (or forced password resets) land here.
        // Cognito rejects immutable attributes on the challenge response.
        delete userAttributes.email_verified;
        delete userAttributes.email;
        pendingNewPassword = {
          user,
          requiredAttributes: Object.keys(userAttributes),
        };
        resolve({ status: 'newPasswordRequired' });
      },
    });
  });
}

/** Completes a NEW_PASSWORD_REQUIRED challenge started by login(). */
export function completeNewPassword(newPassword: string): Promise<CognitoUserSession> {
  return new Promise((resolve, reject) => {
    if (!pendingNewPassword) {
      reject(new Error('no pending new-password challenge'));
      return;
    }
    const { user } = pendingNewPassword;
    user.completeNewPasswordChallenge(
      newPassword,
      {},
      {
        onSuccess: (session) => {
          pendingNewPassword = null;
          resolve(session);
        },
        onFailure: (err) => reject(err),
      }
    );
  });
}

// ---------------------------------------------------------------------------
// Password reset (forgot) + authenticated change
// ---------------------------------------------------------------------------

/** Starts a forgot-password flow; Cognito emails a verification code. */
export function forgotPassword(username: string): Promise<void> {
  return new Promise((resolve, reject) => {
    makeUser(username).forgotPassword({
      onSuccess: () => resolve(),
      onFailure: (err) => reject(err),
      inputVerificationCode: () => resolve(),
    });
  });
}

/** Completes a forgot-password flow with the emailed code + a new password. */
export function confirmForgotPassword(
  username: string,
  code: string,
  newPassword: string
): Promise<void> {
  return new Promise((resolve, reject) => {
    makeUser(username).confirmPassword(code, newPassword, {
      onSuccess: () => resolve(),
      onFailure: (err) => reject(err),
    });
  });
}

/** Changes the password for the currently signed-in user. */
export function changePassword(oldPassword: string, newPassword: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const user = getUserPool().getCurrentUser();
    if (!user) {
      reject(new Error('not signed in'));
      return;
    }
    user.getSession((err: Error | null) => {
      if (err) {
        reject(err);
        return;
      }
      user.changePassword(oldPassword, newPassword, (e) => (e ? reject(e) : resolve()));
    });
  });
}

// ---------------------------------------------------------------------------
// Session + tokens (with seamless refresh) + logout
// ---------------------------------------------------------------------------

/**
 * Returns a VALID session, transparently refreshing expired ID/Access tokens
 * using the refresh token. Returns null if there is no signed-in user or the
 * refresh token itself has expired (full re-login required).
 *
 * getSession() is the key to "seamless refresh": if the cached ID/Access token
 * is expired but a valid refresh token exists, the SDK calls Cognito
 * (InitiateAuth REFRESH_TOKEN_AUTH), updates localStorage, and returns fresh
 * tokens — without surfacing an error to the caller.
 */
export function getValidSession(): Promise<CognitoUserSession | null> {
  return new Promise((resolve) => {
    const user = getUserPool().getCurrentUser();
    if (!user) {
      resolve(null);
      return;
    }
    user.getSession((err: Error | null, session: CognitoUserSession | null) => {
      if (err || !session || !session.isValid()) {
        resolve(null);
        return;
      }
      resolve(session);
    });
  });
}

/** Returns a valid ID token JWT (refreshing if needed), or null. */
export async function getIdToken(): Promise<string | null> {
  const session = await getValidSession();
  return session ? session.getIdToken().getJwtToken() : null;
}

/** Returns a valid access token JWT (refreshing if needed), or null. */
export async function getAccessToken(): Promise<string | null> {
  const session = await getValidSession();
  return session ? session.getAccessToken().getJwtToken() : null;
}

export function currentUsername(): string | null {
  return getUserPool().getCurrentUser()?.getUsername() ?? null;
}

/** Local sign-out: clears tokens from localStorage for this app. */
export function logout(): void {
  getUserPool().getCurrentUser()?.signOut();
}

/**
 * Global sign-out: revokes all of the user's refresh tokens server-side (every
 * device/session), then clears local tokens. Requires a valid session.
 */
export function globalLogout(): Promise<void> {
  return new Promise((resolve) => {
    const user = getUserPool().getCurrentUser();
    if (!user) {
      resolve();
      return;
    }
    user.getSession((err: Error | null) => {
      if (err) {
        user.signOut();
        resolve();
        return;
      }
      user.globalSignOut({
        onSuccess: () => resolve(),
        onFailure: () => {
          user.signOut();
          resolve();
        },
      });
    });
  });
}

/** Decodes a JWT payload (no verification — display only). */
export function decodeJwt(token: string): Record<string, unknown> {
  try {
    const payload = token.split('.')[1];
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return {};
  }
}
