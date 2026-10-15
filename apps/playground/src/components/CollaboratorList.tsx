import type { Collaborator } from '../collab/webrtc-provider';

interface CollaboratorListProps {
  collaborators: Collaborator[];
}

export function CollaboratorList({ collaborators }: CollaboratorListProps) {
  if (collaborators.length === 0) return null;

  return (
    <div className="bg-gray-900 border-t border-gray-800 px-4 py-2">
      <div className="text-xs font-medium text-gray-400 mb-2">Collaborators</div>
      <div className="flex flex-wrap gap-2">
        {collaborators.map((collab) => (
          <div
            key={collab.clientId}
            className="flex items-center gap-2 px-2 py-1 rounded bg-gray-800"
            style={{ borderLeft: `3px solid ${collab.color}` }}
          >
            <div
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: collab.color }}
            />
            <span className="text-sm text-white">{collab.name}</span>
            {collab.cursorPosition && (
              <span className="text-xs text-gray-500">
                L{collab.cursorPosition.lineNumber}:C{collab.cursorPosition.column}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}