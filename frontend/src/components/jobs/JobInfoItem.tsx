export function InfoItem({ label, value }: { label: string; value?: string }) {
  if (!value) return null;
  return (
    <div className="info-item">
      <span className="info-label">{label}:</span>
      <span className="info-value">{value}</span>
    </div>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function formatDurationLabel(seconds: number): string {
  const roundedSeconds = Math.max(0, Math.round(seconds));
  const minutes = Math.floor(roundedSeconds / 60);
  const remainingSeconds = roundedSeconds % 60;

  if (minutes === 0) {
    return `${roundedSeconds}s`;
  }

  if (remainingSeconds === 0) {
    return `${minutes}m`;
  }

  return `${minutes}m ${remainingSeconds}s`;
}
