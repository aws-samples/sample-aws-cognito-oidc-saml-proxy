'use strict';

// seed.js — builds a FAKE, offline Amplify-v6 DefaultTokenStore localStorage entry set so the
// admin SPA renders as an authenticated admin WITHOUT any live Cognito call and WITHOUT touching
// product code. The entries are consumed only by:
//   - AuthContext.tsx -> fetchAuthSession() reading Amplify's default localStorage token store
//   - auth.ts getIdToken() localStorage fast-path feeding the authFetch Bearer header
// Neither path verifies the JWT signature client-side; Amplify only checks `exp`, which is far-future.
//
// NO PII / NO SECRETS: every value is a documented placeholder (example.com, alex@example.com,
// us-east-1_EXAMPLE, the passed-in exampleclientid..., sub all-zeros).

const AUTH_KEY_PREFIX = 'CognitoIdentityServiceProvider';

// Fixed fake principal. A UUID sub avoids any @/.-in-key edge case while still letting the
// display code read `email` from the ID-token payload.
const SUB = '00000000-0000-0000-0000-000000000000';
const EMAIL = 'alex@example.com';
const POOL_ID = 'us-east-1_EXAMPLE';
const REGION = 'us-east-1';
const ISS = `https://cognito-idp.${REGION}.amazonaws.com/${POOL_ID}`;

// base64url (no padding) — enough for the unverified payload read Amplify/decodeJwt perform.
function b64url(obj) {
  return Buffer.from(JSON.stringify(obj))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// An obviously-fake, unsigned 3-part JWT: alg "none", literal non-signature. Far-future exp
// (year 2100) so Amplify treats it as valid and never fires a refresh network call.
function fakeJwt(extraPayload) {
  const header = b64url({ alg: 'none', typ: 'JWT' });
  const payload = b64url({
    sub: SUB,
    email: EMAIL,
    'cognito:groups': ['Admins'],
    'custom:tenant_id': 'demo',
    aud: extraPayload.aud,
    iss: ISS,
    exp: 4102444800, // 2100-01-01T00:00:00Z
    iat: 1700000000,
    ...extraPayload,
  });
  return `${header}.${payload}.FAKE_SIGNATURE_NOT_VERIFIED`;
}

// The authKey family Amplify v6's DefaultTokenStore reads/writes, verified against the installed
// @aws-amplify/auth (TokenStore.mjs: createKeysForAuthStorage over AuthTokenStorageKeys ->
// `${prefix}.${clientId}.${username}.${authKey}`) plus the sibling LastAuthUser key. We seed only
// the subset the app actually consumes; the rest are harmless if absent.
function buildFakeSession(clientId) {
  const idToken = fakeJwt({ token_use: 'id', aud: clientId });
  const accessToken = fakeJwt({ token_use: 'access', aud: clientId, scope: 'openid email profile' });
  const base = `${AUTH_KEY_PREFIX}.${clientId}.${SUB}`;

  const userData = JSON.stringify({
    UserAttributes: [
      { Name: 'email', Value: EMAIL },
      { Name: 'sub', Value: SUB },
    ],
    Username: SUB,
  });

  return {
    [`${AUTH_KEY_PREFIX}.${clientId}.LastAuthUser`]: SUB,
    [`${base}.idToken`]: idToken,
    [`${base}.accessToken`]: accessToken,
    [`${base}.refreshToken`]: 'FAKE_REFRESH_NOT_USED',
    [`${base}.clockDrift`]: '0',
    [`${base}.userData`]: userData,
  };
}

module.exports = { buildFakeSession, SUB, EMAIL };
