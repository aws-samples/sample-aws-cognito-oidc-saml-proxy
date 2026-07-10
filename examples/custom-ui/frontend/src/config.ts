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

function fromEnv(): AppConfig {
  return {
    userPoolId: import.meta.env.VITE_COGNITO_USER_POOL_ID ?? '',
    clientId: import.meta.env.VITE_COGNITO_CLIENT_ID ?? '',
    region: import.meta.env.VITE_COGNITO_REGION ?? '',
    gatewayBaseUrl: import.meta.env.VITE_GATEWAY_BASE_URL,
    gatewayTenant: import.meta.env.VITE_GATEWAY_TENANT,
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
