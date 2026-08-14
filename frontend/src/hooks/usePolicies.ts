import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { deletePolicy, listPolicies, uploadPolicy } from '../services/api';
import { useAuth } from './useAuth';

export function usePolicies() {
  const { token } = useAuth();
  return useQuery({
    queryKey: ['policies'],
    queryFn: () => listPolicies(token as string),
    enabled: token !== null,
  });
}

export function useUploadPolicy() {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (formData: FormData) => uploadPolicy(token as string, formData),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  });
}

export function useDeletePolicy() {
  const { token } = useAuth();
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deletePolicy(token as string, id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['policies'] }),
  });
}
