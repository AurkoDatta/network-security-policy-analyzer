import { useState } from 'react';
import { useUploadPolicy } from '../hooks/usePolicies';
import type { Policy } from '../types/api';

interface UploadFormProps {
  onUploaded: (policy: Policy) => void;
}

export function UploadForm({ onUploaded }: UploadFormProps) {
  const [name, setName] = useState('');
  const [sourceType, setSourceType] = useState<'aws' | 'firewall' | 'iam'>('firewall');
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [succeeded, setSucceeded] = useState(false);
  const upload = useUploadPolicy();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSucceeded(false);
    if (!file) {
      setError('A file is required');
      return;
    }

    const formData = new FormData();
    formData.append('name', name);
    formData.append('source_type', sourceType);
    formData.append('file', file);

    try {
      const policy = await upload.mutateAsync(formData);
      setSucceeded(true);
      onUploaded(policy);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3 rounded border p-4">
      <label className="flex flex-col gap-1 text-sm">
        Policy name
        <input value={name} onChange={(e) => setName(e.target.value)} className="rounded border px-3 py-2" />
      </label>
      <label className="flex flex-col gap-1 text-sm">
        Source type
        <select
          value={sourceType}
          onChange={(e) => setSourceType(e.target.value as 'aws' | 'firewall' | 'iam')}
          className="rounded border px-3 py-2"
        >
          <option value="firewall">Firewall</option>
          <option value="aws">AWS Security Group</option>
          <option value="iam">IAM Policy</option>
        </select>
      </label>
      <label className="flex flex-col gap-1 text-sm">
        File
        <input
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="rounded border px-3 py-2"
        />
      </label>
      {error && <p className="text-red-600">{error}</p>}
      {succeeded && <p className="text-green-600">Policy uploaded successfully.</p>}
      <button type="submit" className="rounded bg-slate-900 px-4 py-2 text-white" disabled={upload.isPending}>
        Upload
      </button>
    </form>
  );
}
