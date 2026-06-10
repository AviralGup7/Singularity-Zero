import { Link } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-center justify-center py-32 text-center gap-6">
      <div className="h-16 w-16 rounded-2xl border border-warn/30 bg-warn/10 flex items-center justify-center text-warn">
        <AlertTriangle size={32} />
      </div>
      <div>
        <h1 className="text-3xl font-black text-text uppercase tracking-widest mb-2">404</h1>
        <p className="text-sm text-muted font-mono uppercase tracking-wider">
          The page you are looking for does not exist.
        </p>
      </div>
      <Link
        to="/"
        className="btn btn-primary px-6 py-2 text-xs font-bold uppercase tracking-wider"
      >
        Return to Dashboard
      </Link>
    </div>
  );
}
