// Real WebAuthn (passkey) sign-in against a Cognito user pool.
//
// This issues the genuine selection-based USER_AUTH → WEB_AUTHN sequence:
//
//   1. InitiateAuth(AuthFlow=USER_AUTH, AuthParameters={ USERNAME, PREFERRED_CHALLENGE=WEB_AUTHN })
//      → Cognito replies with ChallengeName=WEB_AUTHN, a Session, and
//        ChallengeParameters.CREDENTIAL_REQUEST_OPTIONS (a WebAuthn
//        PublicKeyCredentialRequestOptionsJSON string).
//   2. navigator.credentials.get() with those options → the authenticator
//      produces an assertion (AuthenticationResponseJSON).
//   3. RespondToAuthChallenge(ChallengeName=WEB_AUTHN, Session,
//        ChallengeResponses={ USERNAME, CREDENTIAL }) → an ID/Access/Refresh set.
//
// There is NO mocked-success path: every token returned here comes from a real
// Cognito RespondToAuthChallenge response. Enrollment
// (StartWebAuthnRegistration / CompleteWebAuthnRegistration) is out of scope;
// the user is assumed to have a pre-registered passkey.

import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
  RespondToAuthChallengeCommand,
  type RespondToAuthChallengeCommandInput,
} from '@aws-sdk/client-cognito-identity-provider';
import { getConfig } from './config';

// Minimal shapes for the WebAuthn JSON options Cognito returns and the
// assertion JSON it expects back. Kept local so this module stays independent
// of whatever WebAuthn lib typings the DOM happens to expose.
interface PublicKeyCredentialRequestOptionsJSON {
  challenge: string;
  timeout?: number;
  rpId?: string;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: Array<{
    id: string;
    type: string;
    transports?: string[];
  }>;
}

function base64UrlToBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, '=');
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function toRequestOptions(
  json: PublicKeyCredentialRequestOptionsJSON
): PublicKeyCredentialRequestOptions {
  return {
    challenge: base64UrlToBuffer(json.challenge),
    timeout: json.timeout,
    rpId: json.rpId,
    userVerification: json.userVerification,
    allowCredentials: (json.allowCredentials ?? []).map((cred) => ({
      id: base64UrlToBuffer(cred.id),
      type: 'public-key',
      transports: cred.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

// Serializes the assertion into the AuthenticationResponseJSON shape Cognito
// expects as the CREDENTIAL challenge response.
function assertionToJson(credential: PublicKeyCredential): string {
  const response = credential.response as AuthenticatorAssertionResponse;
  const json = {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
      authenticatorData: bufferToBase64Url(response.authenticatorData),
      signature: bufferToBase64Url(response.signature),
      userHandle: response.userHandle ? bufferToBase64Url(response.userHandle) : null,
    },
  };
  return JSON.stringify(json);
}

/**
 * Signs a user in with a pre-registered passkey and returns their ID token JWT.
 * Throws if WebAuthn is unavailable, the user cancels, or Cognito does not
 * complete the challenge. Never returns a token that did not come from Cognito.
 */
export async function signInWithPasskey(username: string): Promise<string> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    throw new Error('This browser does not support passkeys (WebAuthn).');
  }

  const cfg = getConfig();
  const client = new CognitoIdentityProviderClient({ region: cfg.region });

  // Step 1: start selection-based USER_AUTH, preferring the WebAuthn factor.
  const initiate = await client.send(
    new InitiateAuthCommand({
      AuthFlow: 'USER_AUTH',
      ClientId: cfg.clientId,
      AuthParameters: {
        USERNAME: username,
        PREFERRED_CHALLENGE: 'WEB_AUTHN',
      },
    })
  );

  if (initiate.ChallengeName !== 'WEB_AUTHN' || !initiate.Session) {
    throw new Error('The user pool did not offer a passkey challenge for this user.');
  }

  const optionsJson = initiate.ChallengeParameters?.CREDENTIAL_REQUEST_OPTIONS;
  if (!optionsJson) {
    throw new Error('Cognito did not return WebAuthn credential request options.');
  }

  // Step 2: ask the authenticator for an assertion.
  const requestOptions = toRequestOptions(
    JSON.parse(optionsJson) as PublicKeyCredentialRequestOptionsJSON
  );
  const credential = (await navigator.credentials.get({
    publicKey: requestOptions,
  })) as PublicKeyCredential | null;
  if (!credential) {
    throw new Error('No passkey assertion was produced.');
  }

  // Step 3: hand the assertion back to Cognito to complete authentication.
  const respondInput: RespondToAuthChallengeCommandInput = {
    ChallengeName: 'WEB_AUTHN',
    ClientId: cfg.clientId,
    Session: initiate.Session,
    ChallengeResponses: {
      USERNAME: username,
      CREDENTIAL: assertionToJson(credential),
    },
  };
  const respond = await client.send(new RespondToAuthChallengeCommand(respondInput));

  const idToken = respond.AuthenticationResult?.IdToken;
  if (!idToken) {
    throw new Error('Passkey sign-in did not complete (no token returned).');
  }
  return idToken;
}
