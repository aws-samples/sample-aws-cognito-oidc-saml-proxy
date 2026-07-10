// Hand-back to the Federation Gateway after a custom-login (REPLACE-mode) flow.
//
// When the gateway sends an unauthenticated user here, it appends
//   ?return_to=<gateway>/t/{tenant}/(saml|oidc)/login/complete&state=<flowId>
// After the user signs in, we POST the Cognito ID token (plus the echoed state)
// back to return_to so the gateway can verify it, establish the session, and
// resume the original SSO flow.

import { getConfig } from './config';

export interface GatewayHandback {
  returnTo: string;
  state: string;
}

/**
 * Reads return_to + state from the current URL. Returns null if either is
 * missing (i.e. this is a normal login, not a gateway-initiated one).
 */
export function readHandback(search: string): GatewayHandback | null {
  const params = new URLSearchParams(search);
  const returnTo = params.get('return_to');
  const state = params.get('state');
  if (!returnTo || !state) return null;
  return { returnTo, state };
}

/**
 * Guards against this app being abused to leak tokens to an arbitrary origin:
 * return_to must be on the SAME ORIGIN as the configured gateway base URL.
 */
export function isTrustedReturnTo(returnTo: string): boolean {
  const cfg = getConfig();
  if (!cfg.gatewayBaseUrl) return false;
  try {
    return new URL(returnTo).origin === new URL(cfg.gatewayBaseUrl).origin;
  } catch {
    return false;
  }
}

/**
 * Performs a top-level browser form POST of the ID token to the gateway's
 * session-establish endpoint. This NAVIGATES the browser (rather than fetching),
 * so the gateway's response — e.g. the SAML HTTP-POST auto-submit form to the
 * SP's ACS — drives the rest of the flow. A cross-origin fetch would be blocked
 * by CORS and would not navigate.
 */
export function postTokenToGateway(handback: GatewayHandback, idToken: string): void {
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = handback.returnTo;

  const addField = (name: string, value: string) => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    form.appendChild(input);
  };

  addField('id_token', idToken);
  addField('state', handback.state);

  document.body.appendChild(form);
  form.submit();
}

/**
 * SAML IdP-initiated launch: top-level form POST of the ID token + target SP
 * entity ID to the gateway's idp-initiate endpoint. The gateway verifies the
 * token, mints an unsolicited SAML assertion, and auto-POSTs it to the SP's ACS.
 */
export function launchSamlApp(samlEntityId: string, idToken: string, relayState?: string): void {
  const cfg = getConfig();
  if (!cfg.gatewayBaseUrl || !cfg.gatewayTenant) {
    throw new Error('gateway base URL / tenant not configured');
  }
  const action = `${cfg.gatewayBaseUrl.replace(/\/$/, '')}/t/${encodeURIComponent(cfg.gatewayTenant)}/saml/idp-initiate`;

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = action;
  const addField = (name: string, value: string) => {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    form.appendChild(input);
  };
  addField('id_token', idToken);
  addField('entityId', samlEntityId);
  if (relayState) addField('relayState', relayState);
  document.body.appendChild(form);
  form.submit();
}

/**
 * Returns true if `url` is a safe post-auth redirect target: an https URL whose
 * origin matches the gateway or one of the configured launch apps' redirectUrls.
 * Prevents the app from being used as an open redirector.
 */
export function isTrustedRedirect(url: string): boolean {
  const cfg = getConfig();
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return false;
  }
  if (target.protocol !== 'https:') return false;

  const allowed = new Set<string>();
  if (cfg.gatewayBaseUrl) {
    try { allowed.add(new URL(cfg.gatewayBaseUrl).origin); } catch { /* ignore */ }
  }
  for (const app of cfg.apps ?? []) {
    if (app.redirectUrl) {
      try { allowed.add(new URL(app.redirectUrl).origin); } catch { /* ignore */ }
    }
  }
  return allowed.has(target.origin);
}
