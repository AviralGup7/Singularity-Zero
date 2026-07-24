import { Link } from 'react-router-dom';
import { AlertTriangle } from 'lucide-react';

export function NotFoundPage() {
  return (
    <main className="flex flex-col items-center justify-center py-32 text-center gap-6" role="alert">
      <div
        className="h-16 w-16 rounded-2xl border border-warn/30 bg-warn/10 flex items-center justify-center text-warn motion-safe:animate-pulse"
        aria-hidden="true"
      >
        <AlertTriangle size={32} />
      </div>
      <div>
        <h1 className="text-3xl font-black text-text uppercase tracking-widest mb-2">404</h1>
        <p className="text-sm text-muted font-mono uppercase tracking-wider max-w-xs">
          The page you are looking for does not exist.
        </p>
      </div>
      <Link
        to="/"
        className="btn btn-primary px-6 py-2 text-xs font-bold uppercase tracking-wider focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-bg transition-opacity hover:opacity-90 active:opacity-75"
      >
        Return to Dashboard
      </Link>
    </main>
  );
}
