import { authFetch } from '../auth';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

export interface SAMLConfig {
  entityId: string;
  acsUrl: string;
  acsUrls?: string[];
  metadataUrl?: string;
  nameIdFormat: string;
  nameIdSource: string;
  signResponse: boolean;
  signAssertion: boolean;
  encryptAssertion: boolean;
  allowIdpInitiated?: boolean;
  sloUrl?: string;
  sessionDurationSec: number;
  clockSkewSec: number;
}

export interface OIDCConfig {
  redirectURIs: string[];
  postLogoutRedirectURIs?: string[];
  grantTypes: string[];
  responseTypes?: string[];
  scopes: string[];
  tokenEndpointAuthMethod: string;
  idTokenLifetimeSec: number;
  accessTokenLifetimeSec: number;
}

export interface Application {
  id: string;
  displayName: string;
  protocol: string;
  sourceId: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  saml?: SAMLConfig;
  oidc?: OIDCConfig;
  claimMappings?: Array<{ source: string; target: string }>;
  roleMappings?: Array<{ group: string; value: string }>;
  customLoginUrl?: string;
  trustedLoginRedirectUris?: string[];
  // clientSecret is populated ONLY on create/update/rotate responses when a
  // confidential OIDC client secret was just generated. Shown once; never
  // returned on read.
  clientSecret?: string;
}

export interface CreateApplicationInput {
  displayName: string;
  protocol: string;
  sourceId: string;
  saml?: Partial<SAMLConfig>;
  oidc?: Partial<OIDCConfig>;
  claimMappings?: Array<{ source: string; target: string }>;
  roleMappings?: Array<{ group: string; value: string }>;
  customLoginUrl?: string;
  trustedLoginRedirectUris?: string[];
}

export function useApplications() {
  return useQuery({
    queryKey: ['applications'],
    queryFn: async (): Promise<Application[]> => {
      const res = await authFetch('/api/v1/applications');
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      return res.json();
    },
  });
}

export function useApplication(id: string) {
  return useQuery({
    queryKey: ['applications', id],
    queryFn: async (): Promise<Application | undefined> => {
      const res = await authFetch(`/api/v1/applications/${id}`);
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      return res.json();
    },
  });
}

export function useCreateApplication() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: CreateApplicationInput): Promise<Application> => {
      const res = await authFetch('/api/v1/applications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) {
        throw new Error('Failed to create application');
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['applications'] });
    },
  });
}

export function useUpdateApplication() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      data,
    }: {
      id: string;
      data: Partial<CreateApplicationInput>;
    }): Promise<Application> => {
      const res = await authFetch(`/api/v1/applications/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) {
        throw new Error('Failed to update application');
      }
      return res.json();
    },
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['applications'] });
      queryClient.invalidateQueries({ queryKey: ['applications', id] });
    },
  });
}
