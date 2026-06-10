import { apiClient } from './core';

export interface RemediationVerification {
  finding_id: string;
  verified: boolean;
  verification_method: string;
  verified_at: string;
  details?: Record<string, unknown>;
}

export async function verifyRemediation(
  findingId: string,
  signal?: AbortSignal,
): Promise<RemediationVerification> {
  const { data } = await apiClient.post<RemediationVerification>(
    `/api/remediated/${encodeURIComponent(findingId)}/verify`,
    undefined,
    { signal },
  );
  return data;
}
