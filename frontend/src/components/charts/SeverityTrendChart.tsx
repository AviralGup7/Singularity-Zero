import { max } from 'd3-array';
import { scaleLinear } from 'd3-scale';
import { area, curveMonotoneX, curveStepAfter, stack } from 'd3-shape';
import { memo, useMemo, useState } from 'react';
import { useVisual } from '@/context/VisualContext';

export interface SeverityTrendDataPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

interface SeverityTrendChartProps {
  data: SeverityTrendDataPoint[];
}

type SeverityKey = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEVERITY_KEYS: SeverityKey[] = ['critical', 'high', 'medium', 'low', 'info'];

const COLORS: Record<SeverityKey, string> = {
  critical: 'var(--severity-critical, #ff0040)',
  high: 'var(--severity-high, #ff8800)',
  medium: 'var(--severity-medium, #ffcc00)',
  low: 'var(--severity-low, #00cc88)',
  info: 'var(--severity-info, #00aaff)',
};

export const SeverityTrendChart = memo(function SeverityTrendChart({ data }: SeverityTrendChartProps) {
  const { state: visualState } = useVisual();
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const chartData = useMemo(() => {
    if (!data?.length) return [];
    return data.map((d) => ({
      date: d.date,
      critical: d.critical ?? 0,
      high: d.high ?? 0,
      medium: d.medium ?? 0,
      low: d.low ?? 0,
      info: d.info ?? 0,
    }));
  }, [data]);

  const dimensions = useMemo(() => {
    const width = 940;
    const height = 360;
    const margin = { top: 20, right: 24, bottom: 56, left: 48 };
    return {
      width,
      height,
      margin,
      innerWidth: width - margin.left - margin.right,
      innerHeight: height - margin.top - margin.bottom,
    };
  }, []);

  const stacked = useMemo(() => {
    return stack<(typeof chartData)[number], SeverityKey>()
      .keys(SEVERITY_KEYS)(chartData);
  }, [chartData]);

  const yMax = useMemo(() => {
    if (stacked.length === 0) return 1;
    const maxFromStack = max(stacked, (series) => max(series, (pair) => pair[1]) ?? 0) ?? 0;
    return Math.max(1, maxFromStack);
  }, [stacked]);

  const xScale = useMemo(() => {
    const upper = Math.max(chartData.length - 1, 1);
    return scaleLinear().domain([0, upper]).range([0, dimensions.innerWidth]);
  }, [chartData.length, dimensions.innerWidth]);

  const yScale = useMemo(() => {
    return scaleLinear().domain([0, yMax]).nice().range([dimensions.innerHeight, 0]);
  }, [dimensions.innerHeight, yMax]);

  const yTicks = useMemo(() => yScale.ticks(5), [yScale]);

  const areaBuilder = useMemo(() => {
    return area<[number, number]>()
      .x((_, index) => xScale(index))
      .y0((point) => yScale(point[0]))
      .y1((point) => yScale(point[1]))
      .curve(visualState.instability > 0.5 ? curveStepAfter : curveMonotoneX);
  }, [visualState.instability, xScale, yScale]);

  const hoveredPoint = hoveredIndex !== null ? chartData[hoveredIndex] ?? null : null;

  if (!chartData.length) {
    return (
      <div className="chart-card">
        <h3 className="chart-title">Severity Trend</h3>
        <div className="chart-empty">No severity trend data available</div>
      </div>
    );
  }

  return (
    <div className="chart-card">
      <h3 className="chart-title">Severity Trend Over Time</h3>
      <div className="chart-container">
        <svg
          viewBox={`0 0 ${dimensions.width} ${dimensions.height}`}
          className="w-full h-auto"
          role="img"
          aria-label="Severity trend stacked area chart"
        >
          <defs>
            {SEVERITY_KEYS.map((severity) => (
              <linearGradient key={severity} id={`severity-gradient-${severity}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={COLORS[severity]} stopOpacity={0.55} />
                <stop offset="100%" stopColor={COLORS[severity]} stopOpacity={0.04} />
              </linearGradient>
            ))}
          </defs>
          <g transform={`translate(${dimensions.margin.left}, ${dimensions.margin.top})`}>
            {yTicks.map((tick) => (
              <g key={tick} transform={`translate(0, ${yScale(tick)})`}>
                <line
                  x1={0}
                  x2={dimensions.innerWidth}
                  y1={0}
                  y2={0}
                  stroke="var(--line, #333)"
                  strokeDasharray="4 5"
                  opacity={0.35}
                />
                <text
                  x={-10}
                  y={4}
                  textAnchor="end"
                  fill="var(--muted, #888)"
                  fontSize={11}
                >
                  {tick}
                </text>
              </g>
            ))}

            {stacked.map((series) => {
              const severity = series.key as SeverityKey;
              const pathData = areaBuilder(series as [number, number][]) ?? '';
              return (
                <path
                  key={severity}
                  d={pathData}
                  fill={`url(#severity-gradient-${severity})`}
                  stroke={COLORS[severity]}
                  strokeWidth={1.8}
                  opacity={hoveredPoint ? 0.42 : 0.95}
                />
              );
            })}

            {chartData.map((point, index) => {
              const x = xScale(index);
              return (
                <g key={`${point.date}-${index}`}>
                  <rect
                    x={x - dimensions.innerWidth / Math.max(chartData.length - 1, 1) / 2}
                    y={0}
                    width={dimensions.innerWidth / Math.max(chartData.length - 1, 1)}
                    height={dimensions.innerHeight}
                    fill="transparent"
                    onMouseEnter={() => setHoveredIndex(index)}
                    onMouseLeave={() => setHoveredIndex(null)}
                  />
                  {hoveredIndex === index && (
                    <line
                      x1={x}
                      x2={x}
                      y1={0}
                      y2={dimensions.innerHeight}
                      stroke="var(--accent, #00f3ff)"
                      strokeDasharray="3 4"
                      opacity={0.9}
                    />
                  )}
                </g>
              );
            })}

            <line
              x1={0}
              x2={dimensions.innerWidth}
              y1={dimensions.innerHeight}
              y2={dimensions.innerHeight}
              stroke="var(--line, #333)"
              opacity={0.6}
            />
            {chartData.map((point, index) => {
              if (index % Math.max(1, Math.floor(chartData.length / 6)) !== 0 && index !== chartData.length - 1) {
                return null;
              }
              return (
                <text
                  key={`label-${point.date}-${index}`}
                  x={xScale(index)}
                  y={dimensions.innerHeight + 24}
                  textAnchor="middle"
                  fill="var(--muted, #888)"
                  fontSize={11}
                >
                  {point.date}
                </text>
              );
            })}
          </g>
        </svg>
      </div>

      <div className="chart-summary">
        {SEVERITY_KEYS.map((severity) => (
          <span key={severity} className="chart-summary-item">
            <span className="chart-summary-dot" style={{ backgroundColor: COLORS[severity] }} />
            {severity}
          </span>
        ))}
      </div>

      {hoveredPoint && (
        <div className="cyber-tooltip">
          <div className="cyber-tooltip-header">{hoveredPoint.date}</div>
          <div className="cyber-tooltip-body">
            {SEVERITY_KEYS.map((severity) => (
              <div key={severity} className="cyber-tooltip-row">
                <span className="cyber-tooltip-dot" style={{ backgroundColor: COLORS[severity] }} />
                <span className="cyber-tooltip-label">{severity}:</span>
                <span className="cyber-tooltip-value">{hoveredPoint[severity]}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
});
