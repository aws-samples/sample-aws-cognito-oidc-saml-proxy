import { authFetch } from '../auth';
import { useQuery } from '@tanstack/react-query';

export interface AnalyticsOverview {
  totalSPs: number;
  totalAuths: number;
}

export function useAnalyticsOverview() {
  return useQuery({
    queryKey: ['analytics', 'overview'],
    queryFn: async (): Promise<AnalyticsOverview> => {
      const res = await authFetch('/api/v1/analytics/overview');
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      return res.json();
    },
  });
}
