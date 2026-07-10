import { authFetch } from '../auth';
import { useQuery } from '@tanstack/react-query';

export interface FlowStep {
  flowId: string;
  sequence: number;
  stepType: string;
  spEntityId: string;
  userId: string;
  timestamp: string;
  payload?: Record<string, string>;
}

export function useAuditLog() {
  return useQuery({
    queryKey: ['audit-log'],
    queryFn: async (): Promise<FlowStep[]> => {
      const res = await authFetch('/api/v1/debug/audit-log');
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      const data = await res.json();
      return data.events ?? [];
    },
  });
}

export function useFlowDetail(flowId: string | null) {
  return useQuery({
    queryKey: ['audit-log', 'flow', flowId],
    queryFn: async (): Promise<{ flowId: string; steps: FlowStep[] }> => {
      const res = await authFetch(`/api/v1/debug/audit-log/${flowId}`);
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      return res.json();
    },
    enabled: !!flowId,
  });
}
