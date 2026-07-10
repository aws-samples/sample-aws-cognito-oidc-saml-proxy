import { authFetch } from '../auth';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

export interface Tenant {
  slug: string;
  displayName: string;
  plan: string;
  status: string;
  maxApps?: number;
  maxAuthsPerMonth?: number;
  createdAt?: string;
}

export interface CreateTenantInput {
  slug: string;
  displayName: string;
}

/** useTenants lists all tenants (the management API is global for operators). */
export function useTenants() {
  return useQuery({
    queryKey: ['tenants'],
    queryFn: async (): Promise<Tenant[]> => {
      const res = await authFetch('/api/v1/tenants');
      if (!res.ok) throw new Error(`Failed to fetch tenants: ${res.status}`);
      return res.json();
    },
  });
}

export function useCreateTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (input: CreateTenantInput): Promise<Tenant> => {
      const res = await authFetch('/api/v1/tenants', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(body || `Failed to create tenant: ${res.status}`);
      }
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenants'] });
    },
  });
}

export function useDeleteTenant() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (slug: string): Promise<void> => {
      const res = await authFetch(`/api/v1/tenants/${slug}`, { method: 'DELETE' });
      if (!res.ok) {
        const body = await res.text();
        throw new Error(body || `Failed to delete tenant: ${res.status}`);
      }
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tenants'] });
    },
  });
}
