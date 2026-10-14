// Runtime configuration.
//
// In a deployed environment the Go Lambda serves these values at GET /config.json
// (populated from Terraform-provided environment variables), so the same built
// SPA artifact is configured per-environment with no rebuild.
//
// For local `npm run dev` we fall back to Vite build-time env vars (VITE_*).

export interface AppConfig {
  userPoolId: string;
  clientId: string;
  region: string;
  // Optional — only used by the Config page to show gateway wiring.
  gatewayBaseUrl?: string;
  gatewayTenant?: string;
  // Optional — apps shown on the App Launcher page.
  apps?: LaunchApp[];
  // Optional — the Cognito user pool domain (e.g. `example.auth.us-east-1.amazoncognito.com`),
  // used to build /oauth2/authorize URLs for the social-login buttons. When unset the
  // social section on the Login page is hidden entirely.
  cognitoDomain?: string;
  // Optional — social identity providers to offer on the Login page. When unset or empty,
  // no social buttons are shown. Each entry maps to a Cognito user-pool IdP.
  socialIdps?: SocialIdp[];
  // Optional — enable the WebAuthn passkey sign-in button on the Login page. Defaults to off;
  // the button is also disabled when the browser lacks WebAuthn support.
  passkeysEnabled?: boolean;
}

// A social / external identity provider offered on the Login page. `idp` is the exact
// Cognito provider name (e.g. "Google", "SignInWithApple", or a custom SAML/OIDC provider
// name). `color` is an optional CSS color for the button accent.
export interface SocialIdp {
  label: string;
  idp: string;
  color?: string;
}

// A launchable application shown on the App Launcher page.
export interface LaunchApp {
  label: string;
  protocol: 'saml' | 'oidc';
  // SAML IdP-initiated: the SP's SAML entity ID (the gateway mints an
  // unsolicited assertion to this app's ACS).
  samlEntityId?: string;
  // Optional SAML RelayState (e.g. a deep link at the SP).
  relayState?: string;
  // OIDC (and generic): a URL the browser is sent to after authentication
  // (typically the RP's login-start URL). OIDC has no IdP-initiated flow.
  redirectUrl?: string;
}

let cached: AppConfig | null = null;

function parseSocialIdps(raw: string | undefined): SocialIdp[] | undefined {
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as SocialIdp[]) : undefined;
  } catch {
    // Malformed JSON — treat as unset (social section stays hidden).
    return undefined;
  }
}

function fromEnv(): AppConfig {
  return {
    userPoolId: import.meta.env.VITE_COGNITO_USER_POOL_ID ?? '',
    clientId: import.meta.env.VITE_COGNITO_CLIENT_ID ?? '',
    region: import.meta.env.VITE_COGNITO_REGION ?? '',
    gatewayBaseUrl: import.meta.env.VITE_GATEWAY_BASE_URL,
    gatewayTenant: import.meta.env.VITE_GATEWAY_TENANT,
    cognitoDomain: import.meta.env.VITE_COGNITO_DOMAIN,
    socialIdps: parseSocialIdps(import.meta.env.VITE_SOCIAL_IDPS),
    passkeysEnabled: import.meta.env.VITE_PASSKEYS_ENABLED === 'true',
  };
}

/**
 * Loads runtime config. Tries /config.json first (deployed mode); if that is
 * missing or empty, falls back to build-time VITE_* env (local dev).
 */
export async function loadConfig(): Promise<AppConfig> {
  if (cached) return cached;

  try {
    const res = await fetch('/config.json', { cache: 'no-store' });
    if (res.ok) {
      const data = (await res.json()) as Partial<AppConfig>;
      if (data.userPoolId && data.clientId) {
        cached = {
          userPoolId: data.userPoolId,
          clientId: data.clientId,
          region: data.region || data.userPoolId.split('_')[0] || '',
          gatewayBaseUrl: data.gatewayBaseUrl,
          gatewayTenant: data.gatewayTenant,
          apps: Array.isArray(data.apps) ? data.apps : undefined,
          cognitoDomain: data.cognitoDomain,
          socialIdps: Array.isArray(data.socialIdps) ? data.socialIdps : undefined,
          passkeysEnabled: data.passkeysEnabled,
        };
        return cached;
      }
    }
  } catch {
    // ignore — fall back to env
  }

  cached = fromEnv();
  return cached;
}

export function getConfig(): AppConfig {
  if (!cached) {
    throw new Error('config not loaded yet — call loadConfig() first');
  }
  return cached;
}
