import { useNavigate } from 'react-router-dom';
import { UploadForm } from '../components/UploadForm';
import { PolicyTable } from '../components/PolicyTable';
import { usePolicies, useDeletePolicy } from '../hooks/usePolicies';
import { useAnalyzePolicy } from '../hooks/useAnalysis';

export function PoliciesPage() {
  const { data: policies, isLoading, error } = usePolicies();
  const deletePolicy = useDeletePolicy();
  const analyze = useAnalyzePolicy();
  const navigate = useNavigate();

  const handleSelect = async (id: string) => {
    const analysis = await analyze.mutateAsync(id);
    navigate(`/analyses/${analysis._id}`);
  };

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-6 px-4 py-8">
      <h1 className="text-2xl font-semibold">Policies</h1>
      <UploadForm onUploaded={() => undefined} />
      {isLoading && <p>Loading policies…</p>}
      {error && <p className="text-red-600">{(error as Error).message}</p>}
      {policies && <PolicyTable policies={policies} onSelect={handleSelect} onDelete={(id) => deletePolicy.mutate(id)} />}
    </div>
  );
}
