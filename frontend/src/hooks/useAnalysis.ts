import { useMutation } from '@tanstack/react-query';
import type { Analysis } from '../types/api';

export function useAnalyzePolicy() {
  return useMutation<Analysis, Error, string>({
    mutationFn: () => {
      throw new Error('not implemented until Task 4');
    },
  });
}
