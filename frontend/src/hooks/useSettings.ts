import { authFetch } from '../auth';
import { useQuery } from '@tanstack/react-query';

export interface GatewaySettings {
  tenant: {
    slug: string;
    displayName: string;
    plan: string;
    maxApps: number;
    maxAuthsPerMonth: number;
    defaultSessionDurationSec: number;
    defaultSignResponse: boolean;
    defaultSignAssertion: boolean;
    defaultNameIdFormat: string;
    defaultIdTokenLifetimeSec: number;
    defaultAccessTokenLifetimeSec: number;
    defaultScopes: string[];
  };
  gateway: {
    entityId: string;
    baseUrl: string;
    kmsKeyId: string;
    kmsKeyIdBackup?: string;
    samlMetadataUrl: string;
    oidcDiscoveryUrl: string;
  };
}

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: async (): Promise<GatewaySettings> => {
      const res = await authFetch('/api/v1/settings');
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      return res.json();
    },
  });
}
