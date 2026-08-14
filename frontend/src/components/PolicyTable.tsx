import type { Policy } from '../types/api';

interface PolicyTableProps {
  policies: Policy[];
  onSelect: (id: string) => void;
  onDelete: (id: string) => void;
}

export function PolicyTable({ policies, onSelect, onDelete }: PolicyTableProps) {
  if (policies.length === 0) {
    return <p className="text-slate-500">No policies uploaded yet.</p>;
  }

  return (
    <table className="w-full border-collapse text-left">
      <thead>
        <tr className="border-b">
          <th className="py-2">Name</th>
          <th className="py-2">Source</th>
          <th className="py-2">Rules</th>
          <th className="py-2" />
        </tr>
      </thead>
      <tbody>
        {policies.map((policy) => (
          <tr key={policy._id} className="border-b">
            <td className="cursor-pointer py-2 underline" onClick={() => onSelect(policy._id)}>
              {policy.name}
            </td>
            <td className="py-2">{policy.source_type}</td>
            <td className="py-2">{policy.normalized_rules.length}</td>
            <td className="py-2">
              <button
                type="button"
                onClick={() => onDelete(policy._id)}
                className="rounded border px-2 py-1 text-sm text-red-600"
              >
                Delete
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
