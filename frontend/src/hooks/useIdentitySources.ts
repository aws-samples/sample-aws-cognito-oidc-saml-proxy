import { authFetch } from '../auth';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

export interface IdentitySource {
  id: string;
  displayName: string;
  type: string;
  region: string;
  poolId: string;
  domain: string;
  clientId: string;
  status: 'active' | 'error';
  createdAt: string;
  updatedAt?: string;
}

export interface CreateIdentitySourceInput {
  displayName: string;
  poolId: string;
  region: string;
  clientId: string;
  domain?: string;
}

export interface TestConnectionResult {
  reachable: boolean;
  latencyMs?: number;
  error?: string;
}

export interface DiscoverPoolInput {
  poolId: string;
  region: string;
}

export interface DiscoverPoolResult {
  domain: string;
  attributes: string[];
}

export function useIdentitySources() {
  return useQuery({
    queryKey: ['identity-sources'],
    queryFn: async (): Promise<IdentitySource[]> => {
      const res = await authFetch('/api/v1/identity-sources');
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      return res.json();
    },
  });
}

export function useIdentitySource(id: string) {
  return useQuery({
    queryKey: ['identity-sources', id],
    queryFn: async (): Promise<IdentitySource> => {
      const res = await authFetch(`/api/v1/identity-sources/${id}`);
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      return res.json();
    },
  });
}

export function useCreateIdentitySource() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: CreateIdentitySourceInput): Promise<IdentitySource> => {
      const res = await authFetch('/api/v1/identity-sources', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) {
        throw new Error('Failed to create identity source');
      }
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-sources'] });
    },
  });
}

export function useUpdateIdentitySource() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({
      id,
      data,
    }: {
      id: string;
      data: Partial<CreateIdentitySourceInput>;
    }): Promise<IdentitySource> => {
      const res = await authFetch(`/api/v1/identity-sources/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) {
        throw new Error('Failed to update identity source');
      }
      return res.json();
    },
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['identity-sources'] });
      queryClient.invalidateQueries({ queryKey: ['identity-sources', id] });
    },
  });
}

export function useDeleteIdentitySource() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: string): Promise<void> => {
      const res = await authFetch(`/api/v1/identity-sources/${id}`, {
        method: 'DELETE',
      });
      if (!res.ok) {
        throw new Error('Failed to delete identity source');
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['identity-sources'] });
    },
  });
}

export function useTestConnection() {
  return useMutation({
    mutationFn: async (id: string): Promise<TestConnectionResult> => {
      const res = await authFetch(`/api/v1/identity-sources/${id}/test`, { method: 'POST' });
      if (!res.ok) throw new Error(`Failed: ${res.status}`);
      return res.json();
    },
  });
}

export function useDiscoverPool() {
  return useMutation({
    mutationFn: async (data: DiscoverPoolInput): Promise<DiscoverPoolResult> => {
      const res = await authFetch('/api/v1/identity-sources/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error(`Failed to discover pool: ${res.status}`);
      return res.json();
    },
  });
}
