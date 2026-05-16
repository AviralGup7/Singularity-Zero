import { useMemo } from 'react';

interface TrendDataPoint {
  date: string;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  scans: number;
}

interface DashboardTrendChartsProps {
  data: TrendDataPoint[];
}

function BarChart({ data, width, height, maxVal }: { data: number[]; width: number; height: number; maxVal: number }) {
  if (data.length === 0) return null;
  const barWidth = Math.max(4, (width - data.length * 2) / data.length);
  const bars = data.map((val, i) => {
    const barHeight = maxVal > 0 ? (val / maxVal) * (height - 20) : 0;
    const x = i * (barWidth + 2);
    const y = height - barHeight - 15;
    return (
      <rect
        key={i}
        x={x}
        y={y}
        width={barWidth}
        height={barHeight}
        className="trend-bar"
        rx={1}
      />
    );
  });
  const labels = data.map((_, i) => {
    const x = i * (barWidth + 2) + barWidth / 2;
    return (
      <text key={i} x={x} y={height - 2} className="trend-label" textAnchor="middle" fontSize={8}>
        {i + 1}
      </text>
    );
  });
  return (
    <svg width={width} height={height} className="trend-svg">
      {bars}
      {labels}
    </svg>
  );
}

function StackedBarChart({ data, width, height, maxVal }: { data: Array<{ critical: number; high: number; medium: number; low: number; info: number }>; width: number; height: number; maxVal: number }) {
  if (data.length === 0) return null;
  const barWidth = Math.max(4, (width - data.length * 2) / data.length);
  const elements: React.ReactElement[] = [];
  const colors = {
    critical: 'var(--severity-critical)',
    high: 'var(--severity-high)',
    medium: 'var(--severity-medium)',
    low: 'var(--severity-low)',
    info: 'var(--severity-info)',
  };
  const keys: Array<keyof typeof colors> = ['critical', 'high', 'medium', 'low', 'info'];

  data.forEach((point, i) => {
    let cumulativeHeight = 0;
    keys.forEach(key => {
      const val = Reflect.get(point, key) as number;
      const barH = maxVal > 0 ? (val / maxVal) * (height - 20) : 0;
      const x = i * (barWidth + 2);
      const y = height - cumulativeHeight - barH - 15;
      elements.push(
        <rect key={`${i}-${key}`} x={x} y={y} width={barWidth} height={barH} fill={colors[key]} rx={1} />
      );
      cumulativeHeight += barH;
    });
    elements.push(
      <text key={`label-${i}`} x={i * (barWidth + 2) + barWidth / 2} y={height - 2} className="trend-label" textAnchor="middle" fontSize={8}>
        {i + 1}
      </text>
    );
  });

  return (
    <svg width={width} height={height} className="trend-svg">
      {elements}
    </svg>
  );
}

function LineChart({ data, width, height, maxVal }: { data: number[]; width: number; height: number; maxVal: number }) {
  if (data.length < 2) return null;
  const points = data.map((val, i) => {
    const x = i * (width / Math.max(1, data.length - 1));
    const y = maxVal > 0 ? height - (val / maxVal) * (height - 20) - 15 : height - 15;
    return `${x},${y}`;
  }).join(' ');

  const dots = data.map((val, i) => {
    const x = i * (width / Math.max(1, data.length - 1));
    const y = maxVal > 0 ? height - (val / maxVal) * (height - 20) - 15 : height - 15;
    return <circle key={i} cx={x} cy={y} r={3} className="trend-dot" />;
  });

  return (
    <svg width={width} height={height} className="trend-svg">
      <polyline points={points} className="trend-line" fill="none" strokeWidth={2} />
      {dots}
    </svg>
  );
}

export function DashboardTrendCharts({ data }: DashboardTrendChartsProps) {
  const chartWidth = 400;
  const chartHeight = 120;

  const maxFindings = useMemo(() => Math.max(1, ...data.map(d => d?.findings ?? 0)), [data]);
  const maxScans = useMemo(() => Math.max(1, ...data.map(d => d?.scans ?? 0)), [data]);

  const findingData = useMemo(() => data.map(d => d?.findings ?? 0), [data]);
  const scanData = useMemo(() => data.map(d => d?.scans ?? 0), [data]);
  const severityData = useMemo(() => data.map(d => ({
    critical: d?.critical ?? 0,
    high: d?.high ?? 0,
    medium: d?.medium ?? 0,
    low: d?.low ?? 0,
    info: d?.info ?? 0,
  })), [data]);

  if (data.length === 0) {
    return (
      <div className="card empty">
        <p>No trend data available.</p>
      </div>
    );
  }

  const totalFindings = data.reduce((sum, d) => sum + (d?.findings ?? 0), 0);

  return (
    <div className="dashboard-trend-charts">
      <h3 className="trend-charts-title" data-focus-heading>📊 Trend Analysis</h3>

      <div className="trend-charts-grid">
        <div className="trend-chart-card">
          <h4 className="trend-chart-label">Finding Count Over Time</h4>
          <LineChart data={findingData} width={chartWidth} height={chartHeight} maxVal={maxFindings} />
          <div className="trend-chart-footer">
            <span>Total: {totalFindings} findings</span>
            <span>Avg: {Math.round(totalFindings / Math.max(1, data.length))} per period</span>
          </div>
        </div>

        <div className="trend-chart-card">
          <h4 className="trend-chart-label">Severity Distribution</h4>
          <StackedBarChart data={severityData} width={chartWidth} height={chartHeight} maxVal={maxFindings} />
          <div className="trend-chart-legend">
            <span className="trend-legend-item"><span className="trend-legend-dot trend-legend-critical" /> Critical</span>
            <span className="trend-legend-item"><span className="trend-legend-dot trend-legend-high" /> High</span>
            <span className="trend-legend-item"><span className="trend-legend-dot trend-legend-medium" /> Medium</span>
            <span className="trend-legend-item"><span className="trend-legend-dot trend-legend-low" /> Low</span>
            <span className="trend-legend-item"><span className="trend-legend-dot trend-legend-info" /> Info</span>
          </div>
        </div>

        <div className="trend-chart-card">
          <h4 className="trend-chart-label">Scan Frequency</h4>
          <BarChart data={scanData} width={chartWidth} height={chartHeight} maxVal={maxScans} />
          <div className="trend-chart-footer">
            <span>Total scans: {data.reduce((sum, d) => sum + (d?.scans ?? 0), 0)}</span>
            <span>Periods: {data.length}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
