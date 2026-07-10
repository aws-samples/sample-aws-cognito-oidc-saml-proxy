import { authFetch } from '../auth';
import { useQuery } from '@tanstack/react-query';

export interface DashboardStats {
  sourceCount: number;
  appCount: number;
  unhealthySources: number;
  certDaysRemaining: number;
  certIsExpired: boolean;
  totalAuths: number;
}

export interface FlowStep {
  flowId: string;
  stepType: string;
  userId: string;
  spEntityId: string;
  timestamp: string;
  payload?: Record<string, string>;
}

export interface GatewayInfo {
  gateway: {
    entityId: string;
    baseUrl: string;
    kmsKeyId: string;
    samlMetadataUrl: string;
    oidcDiscoveryUrl: string;
  };
  tenant: {
    slug: string;
    displayName: string;
  };
}

export function useDashboardStats() {
  return useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: async (): Promise<DashboardStats> => {
      const [sourcesRes, appsRes, certRes, analyticsRes] = await Promise.all([
        authFetch('/api/v1/identity-sources'),
        authFetch('/api/v1/applications'),
        authFetch('/api/v1/health/certificates').catch(() => null),
        authFetch('/api/v1/analytics/overview').catch(() => null),
      ]);
      const sources = sourcesRes.ok ? await sourcesRes.json() : [];
      const apps = appsRes.ok ? await appsRes.json() : [];
      const certData = certRes?.ok ? await certRes.json() : null;
      const analytics = analyticsRes?.ok ? await analyticsRes.json() : null;
      const unhealthy = Array.isArray(sources) ? sources.filter((s: any) => s.status !== 'active').length : 0;
      // Cert API returns { certificates: [...] } — find the active cert
      const activeCert = certData?.certificates?.find((c: any) => c.status === 'active') ?? certData?.certificates?.[0] ?? null;
      return {
        sourceCount: Array.isArray(sources) ? sources.length : 0,
        appCount: Array.isArray(apps) ? apps.length : 0,
        unhealthySources: unhealthy,
        certDaysRemaining: activeCert?.daysRemaining ?? 0,
        certIsExpired: activeCert?.isExpired ?? false,
        totalAuths: analytics?.totalAuths ?? 0,
      };
    },
  });
}

export function useRecentEvents() {
  return useQuery({
    queryKey: ['dashboard', 'recent-events'],
    queryFn: async (): Promise<FlowStep[]> => {
      const res = await authFetch('/api/v1/debug/audit-log');
      if (!res.ok) return [];
      const data = await res.json();
      return (data.events ?? []).slice(0, 10);
    },
  });
}

export function useGatewayInfo() {
  return useQuery<GatewayInfo>({
    queryKey: ['settings'],
    queryFn: async () => {
      const res = await authFetch('/api/v1/settings');
      if (!res.ok) throw new Error('Failed to fetch settings');
      return res.json();
    },
  });
}
