import { max } from 'd3-array';
import { scaleBand, scaleLinear } from 'd3-scale';
import { memo, useMemo, useState } from 'react';

export interface ModulePerformanceDataPoint {
  module: string;
  duration: number;
  findings: number;
}

interface ModulePerformanceChartProps {
  data: ModulePerformanceDataPoint[];
}

const BAR_COLORS = [
  'var(--accent, #00f3ff)',
  'var(--accent-2, #00ff88)',
  'var(--severity-critical, #ff0040)',
  'var(--severity-high, #ff8800)',
  'var(--severity-medium, #ffcc00)',
  'var(--severity-low, #00cc88)',
  'var(--severity-info, #00aaff)',
  'var(--accent-vibrant, #bf00ff)',
];

export const ModulePerformanceChart = memo(function ModulePerformanceChart({ data }: ModulePerformanceChartProps) {
   
  const [hoveredModule, setHoveredModule] = useState<string | null>(null);
  const chartData = useMemo(() => {
    if (!data?.length) return [];
    return data.map((d, i) => ({
      name: d.module,
      duration: d.duration ?? 0,
      findings: d.findings ?? 0,
      colorIndex: i % BAR_COLORS.length,
    }));
   
  }, [data]);

  const dimensions = useMemo(() => {
    const margin = { top: 20, right: 32, bottom: 48, left: 160 };
    const rowHeight = 28;
    const chartHeight = Math.max(250, chartData.length * rowHeight + margin.top + margin.bottom);
    const chartWidth = 960;
    return {
      width: chartWidth,
      height: chartHeight,
      margin,
      innerWidth: chartWidth - margin.left - margin.right,
      innerHeight: chartHeight - margin.top - margin.bottom,
    };
   
  }, [chartData.length]);

  const yScale = useMemo(() => {
    return scaleBand<string>()
      .domain(chartData.map((entry) => entry.name))
   
      .range([0, dimensions.innerHeight])
      .paddingInner(0.22);
   
  }, [chartData, dimensions.innerHeight]);

  const xScale = useMemo(() => {
    const maxDuration = max(chartData, (entry) => entry.duration) ?? 0;
    const maxFindings = max(chartData, (entry) => entry.findings) ?? 0;
    const upperBound = Math.max(1, maxDuration, maxFindings);
   
    return scaleLinear().domain([0, upperBound]).nice().range([0, dimensions.innerWidth]);
   
  }, [chartData, dimensions.innerWidth]);

   
  const xTicks = useMemo(() => xScale.ticks(5), [xScale]);
  const hovered = useMemo(
    () => chartData.find((entry) => entry.name === hoveredModule) ?? null,
   
    [chartData, hoveredModule]
  );

  if (!chartData.length) {
    return (
      <div className="chart-card">
        <h3 className="chart-title">Module Performance</h3>
        <div className="chart-empty">No module performance data available</div>
      </div>
    );
  }

  return (
    <div className="chart-card">
      <h3 className="chart-title">Module Performance</h3>
      <div className="chart-container">
        <svg
          viewBox={`0 0 ${dimensions.width} ${dimensions.height}`}
          className="w-full h-auto"
          role="img"
          aria-label="Module performance chart for runtime and findings"
        >
          <g transform={`translate(${dimensions.margin.left}, ${dimensions.margin.top})`}>
            {xTicks.map((tick) => {
              const x = xScale(tick);
              return (
                <g key={tick} transform={`translate(${x},0)`}>
                  <line
                    y1={0}
                    y2={dimensions.innerHeight}
                    stroke="var(--line, #333)"
                    strokeDasharray="4 5"
                    opacity={0.4}
                  />
                  <text
                    y={dimensions.innerHeight + 22}
                    textAnchor="middle"
                    fill="var(--muted, #888)"
                    fontSize={11}
                  >
                    {tick}
                  </text>
                </g>
              );
            })}

            {chartData.map((entry, index) => {
              const y = yScale(entry.name) ?? 0;
              const band = yScale.bandwidth();
              const half = Math.max(4, band / 2 - 3);
              const isHovered = hoveredModule === entry.name;
              return (
                <g
                  key={entry.name}
                  transform={`translate(0, ${y})`}
                  onMouseEnter={() => setHoveredModule(entry.name)}
                  onMouseLeave={() => setHoveredModule(null)}
                  opacity={hoveredModule && !isHovered ? 0.35 : 1}
                >
                  <text
                    x={-12}
                    y={band / 2 + 4}
                    textAnchor="end"
                    fill="var(--text, #f8f8ff)"
                    fontSize={11}
                  >
                    {entry.name}
                  </text>
                  <rect
                    x={0}
                    y={0}
                    width={xScale(entry.duration)}
                    height={half}
                    rx={4}
   
                    fill={BAR_COLORS[index % BAR_COLORS.length]}
                    fillOpacity={0.82}
                  />
                  <rect
                    x={0}
                    y={band - half}
                    width={xScale(entry.findings)}
                    height={half}
                    rx={4}
   
                    fill={BAR_COLORS[(index + 3) % BAR_COLORS.length]}
                    fillOpacity={0.64}
                  />
                </g>
              );
            })}
          </g>
        </svg>
      </div>
      <div className="chart-summary">
        <span className="chart-summary-item">
  // eslint-disable-next-line security/detect-object-injection
          <span className="chart-summary-dot" style={{ backgroundColor: BAR_COLORS[0] }} />
          Duration (s)
        </span>
        <span className="chart-summary-item">
  // eslint-disable-next-line security/detect-object-injection
          <span className="chart-summary-dot" style={{ backgroundColor: BAR_COLORS[3] }} />
          Findings
        </span>
      </div>
      {hovered && (
        <div className="cyber-tooltip">
          <div className="cyber-tooltip-header">{hovered.name}</div>
          <div className="cyber-tooltip-body">
            <div className="cyber-tooltip-row">
  // eslint-disable-next-line security/detect-object-injection
              <span className="cyber-tooltip-dot" style={{ backgroundColor: BAR_COLORS[0] }} />
              <span className="cyber-tooltip-label">duration:</span>
              <span className="cyber-tooltip-value">{hovered.duration.toFixed(2)}s</span>
            </div>
            <div className="cyber-tooltip-row">
  // eslint-disable-next-line security/detect-object-injection
              <span className="cyber-tooltip-dot" style={{ backgroundColor: BAR_COLORS[3] }} />
              <span className="cyber-tooltip-label">findings:</span>
              <span className="cyber-tooltip-value">{hovered.findings}</span>
            </div>
          </div>
        </div>
      )}
      <div className="chart-summary">
        <span className="chart-summary-item">Built with D3 scales and SVG rendering.</span>
      </div>
    </div>
  );
});
