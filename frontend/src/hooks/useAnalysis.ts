import { useMutation, useQuery } from '@tanstack/react-query';
import { getAnalysis, triggerAnalysis } from '../services/api';
import { useAuth } from './useAuth';
import type { Analysis } from '../types/api';

export function useAnalysis(id: string | undefined) {
  const { token } = useAuth();
  return useQuery({
    queryKey: ['analyses', id],
    queryFn: () => getAnalysis(token as string, id as string),
    enabled: token !== null && id !== undefined,
  });
}

export function useAnalyzePolicy() {
  const { token } = useAuth();
  return useMutation<Analysis, Error, string>({
    mutationFn: (policyId: string) => triggerAnalysis(token as string, policyId),
  });
}
