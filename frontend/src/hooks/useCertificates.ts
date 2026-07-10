import { authFetch } from '../auth';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

export type CertRole = 'active' | 'backup';

export interface CertEntry {
  id: string;
  role: CertRole;
  status: 'active' | 'backup' | 'pending' | 'grace' | 'retired';
  source: 'self-signed' | 'ca-issued';
  kmsKeyId?: string;
  subject: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  fingerprint: string;
  daysRemaining: number;
  isExpired: boolean;
  pemBase64: string;
}

export function useCertificates() {
  return useQuery({
    queryKey: ['certificates'],
    queryFn: async (): Promise<CertEntry[]> => {
      const res = await authFetch('/api/v1/health/certificates');
      if (!res.ok) throw new Error(`Failed to fetch certificates: ${res.status}`);
      const data = await res.json();
      return data.certificates ?? [];
    },
  });
}

async function parseError(res: Response, fallback: string): Promise<string> {
  try {
    const data = await res.json();
    return data.detail || data.message || fallback;
  } catch {
    return fallback;
  }
}

// useGenerateCSR returns the PEM-encoded CSR for the given role's KMS key.
export function useGenerateCSR() {
  return useMutation({
    mutationFn: async (role: CertRole): Promise<{ role: string; csrPem: string }> => {
      const res = await authFetch('/api/v1/certificates/csr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role }),
      });
      if (!res.ok) throw new Error(await parseError(res, `Failed to generate CSR: ${res.status}`));
      return res.json();
    },
  });
}

// useImportCertificate imports a CA-issued leaf certificate for a role.
export function useImportCertificate() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (input: { role: CertRole; certPem: string }) => {
      const res = await authFetch('/api/v1/certificates/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      if (!res.ok) throw new Error(await parseError(res, `Failed to import certificate: ${res.status}`));
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
    },
  });
}

// usePromoteBackup promotes the standby backup certificate to active.
export function usePromoteBackup() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await authFetch('/api/v1/certificates/promote-backup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) throw new Error(await parseError(res, `Failed to promote backup: ${res.status}`));
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] });
    },
  });
}
