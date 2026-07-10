import { authFetch } from '../auth';
import { useQuery } from '@tanstack/react-query';

export interface SAMLIntegration {
  metadataUrl: string;
  appMetadataUrl: string;
  entityId: string;
  ssoUrl: string;
  sloUrl: string;
  certificateFingerprint: string;
  nameIdFormat: string;
}

export interface OIDCIntegration {
  discoveryUrl: string;
  clientId: string;
  authorizationUrl: string;
  tokenUrl: string;
  jwksUrl: string;
  userinfoUrl: string;
  scopes: string[];
}

export interface IntegrationInfo {
  application: {
    id: string;
    displayName: string;
    protocol: string;
  };
  saml?: SAMLIntegration;
  oidc?: OIDCIntegration;
  quickStart?: Record<string, string>;
}

export function useIntegration(appId: string) {
  return useQuery({
    queryKey: ['integration', appId],
    queryFn: async (): Promise<IntegrationInfo> => {
      const res = await authFetch(`/api/v1/applications/${appId}/integration`);
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      return res.json();
    },
    enabled: !!appId,
  });
}
