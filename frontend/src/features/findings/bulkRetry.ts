import type { Finding } from '@/types/api';

export interface FailedBulkAction {
  ids: string[];
  action: string;
  data: Partial<Finding>;
  successMsg: string;
}

export function buildFailedBulkAction(
  ids: string[],
  data: Partial<Finding>,
  successMsg: string,
  action: string,
): FailedBulkAction {
  return { ids, action, data, successMsg };
}
