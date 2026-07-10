// Active-tenant selection for the console's tenant switcher.
//
// The management API resolves the tenant from the caller's verified Cognito
// token by default. A genuinely global operator (GlobalOperators group) can
// target a different tenant; authFetch only attaches the X-Tenant-Id override
// when the session actually holds that role, and the server independently
// validates it. The chosen tenant is persisted in localStorage so
// it survives reloads.

const ACTIVE_TENANT_KEY = 'fedgw.activeTenant';

/** DEFAULT_TENANT_SLUG mirrors the backend's built-in default tenant. */
export const DEFAULT_TENANT_SLUG = 'default';

/** getActiveTenant returns the operator-selected tenant slug, or null if none. */
export function getActiveTenant(): string | null {
  try {
    return localStorage.getItem(ACTIVE_TENANT_KEY);
  } catch {
    return null;
  }
}

/** setActiveTenant persists (or clears) the operator-selected tenant slug. */
export function setActiveTenant(slug: string | null): void {
  try {
    if (slug) {
      localStorage.setItem(ACTIVE_TENANT_KEY, slug);
    } else {
      localStorage.removeItem(ACTIVE_TENANT_KEY);
    }
  } catch {
    /* localStorage unavailable — fall back to token-derived tenant only */
  }
}
