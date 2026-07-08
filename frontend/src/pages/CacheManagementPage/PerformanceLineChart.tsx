import { clampPercent } from './helpers';

interface PerformanceLineChartProps {
  data: { time: string; hit: number; miss: number }[];
  animate: boolean;
}

export function PerformanceLineChart({ data, animate }: PerformanceLineChartProps) {
  if (data.length === 0) {
    return <div className="grid h-full place-items-center text-sm text-[var(--muted)]">No samples yet</div>;
  }

  const width = 800;
  const height = 240;
  const padding = { top: 18, right: 22, bottom: 34, left: 42 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const xFor = (index: number) => padding.left + (data.length === 1 ? 0 : (index / (data.length - 1)) * chartWidth);
  const yFor = (value: number) => padding.top + (1 - clampPercent(value) / 100) * chartHeight;
  const pathFor = (key: 'hit' | 'miss') => data.map((point, index) => `${xFor(index)},${yFor(point[key])}`).join(' ');
  const xTicks = data.filter((_, index) => index === 0 || index === data.length - 1 || index % Math.max(1, Math.floor(data.length / 4)) === 0);

  return (
    <svg className="h-full w-full" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img" aria-label="Cache hit and miss rate history">
      <title>Cache performance history</title>
      {[0, 25, 50, 75, 100].map(tick => (
        <g key={tick}>
          <line x1={padding.left} x2={width - padding.right} y1={yFor(tick)} y2={yFor(tick)} stroke="var(--line)" strokeDasharray="4 4" />
          <text x={padding.left - 10} y={yFor(tick) + 4} textAnchor="end" fill="var(--muted)" fontSize="11">{tick}%</text>
        </g>
      ))}
      {xTicks.map(point => {
        const index = data.indexOf(point);
        return (
          <text key={`${point.time}-${index}`} x={xFor(index)} y={height - 10} textAnchor="middle" fill="var(--muted)" fontSize="11">
            {point.time}
          </text>
        );
      })}
      <polyline points={pathFor('hit')} fill="none" stroke="var(--ok)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"
        className={animate ? 'transition-all duration-300' : undefined} />
      <polyline points={pathFor('miss')} fill="none" stroke="var(--warn)" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"
        className={animate ? 'transition-all duration-300' : undefined} />
      <g transform={`translate(${width - 160} 16)`}>
        <circle cx="0" cy="0" r="4" fill="var(--ok)" />
        <text x="10" y="4" fill="var(--text)" fontSize="12">Hit</text>
        <circle cx="58" cy="0" r="4" fill="var(--warn)" />
        <text x="68" y="4" fill="var(--text)" fontSize="12">Miss</text>
      </g>
    </svg>
  );
}
