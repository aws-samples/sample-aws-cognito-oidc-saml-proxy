/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_COGNITO_USER_POOL_ID?: string;
  readonly VITE_COGNITO_CLIENT_ID?: string;
  readonly VITE_COGNITO_REGION?: string;
  readonly VITE_GATEWAY_BASE_URL?: string;
  readonly VITE_GATEWAY_TENANT?: string;
  readonly VITE_COGNITO_DOMAIN?: string;
  readonly VITE_SOCIAL_IDPS?: string;
  readonly VITE_PASSKEYS_ENABLED?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
