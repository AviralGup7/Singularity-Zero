import { max } from 'd3-array';
import { memo, useMemo, useState } from 'react';

export interface FindingsRadarDataPoint {
  category: string;
  count: number;
}

interface FindingsRadarChartProps {
  data: FindingsRadarDataPoint[];
}

const RADAR_FILL = 'var(--accent, #00f3ff)';
const RADAR_STROKE = 'var(--accent-vibrant, #bf00ff)';
const RADAR_DOT_FILL = 'var(--accent, #00f3ff)';

export const FindingsRadarChart = memo(function FindingsRadarChart({ data }: FindingsRadarChartProps) {
   
  const [hoveredCategory, setHoveredCategory] = useState<string | null>(null);

  const chartData = useMemo(() => {
    if (!data?.length) return [];
    return data.map((d) => ({
      category: d.category,
      count: d.count ?? 0,
    }));
   
  }, [data]);

  const dimensions = useMemo(() => {
    const width = 700;
    const height = 420;
    return {
      width,
      height,
      centerX: width / 2,
      centerY: height / 2 + 8,
      radius: 140,
    };
  }, []);

   
  const valueMax = useMemo(() => Math.max(1, max(chartData, (entry) => entry.count) ?? 0), [chartData]);

  const radarPoints = useMemo(() => {
    const count = chartData.length || 1;
    return chartData.map((entry, index) => {
      const angle = (-Math.PI / 2) + (index / count) * Math.PI * 2;
      const normalized = entry.count / valueMax;
      const pointRadius = normalized * dimensions.radius;
      return {
        ...entry,
        angle,
        x: dimensions.centerX + Math.cos(angle) * pointRadius,
        y: dimensions.centerY + Math.sin(angle) * pointRadius,
        labelX: dimensions.centerX + Math.cos(angle) * (dimensions.radius + 24),
        labelY: dimensions.centerY + Math.sin(angle) * (dimensions.radius + 24),
      };
    });
   
  }, [chartData, dimensions.centerX, dimensions.centerY, dimensions.radius, valueMax]);

  const polygonPath = useMemo(() => {
    if (radarPoints.length === 0) return '';
    return radarPoints
      .map((point, index) => `${index === 0 ? 'M' : 'L'} ${point.x} ${point.y}`)
      .join(' ') + ' Z';
   
  }, [radarPoints]);

  const hovered = useMemo(
    () => radarPoints.find((point) => point.category === hoveredCategory) ?? null,
   
    [radarPoints, hoveredCategory]
  );

  if (!chartData.length) {
    return (
      <div className="chart-card">
        <h3 className="chart-title">Findings Distribution</h3>
        <div className="chart-empty">No findings distribution data available</div>
      </div>
    );
  }

  return (
    <div className="chart-card">
      <h3 className="chart-title">Findings Distribution</h3>
      <div className="chart-container">
        <svg
          viewBox={`0 0 ${dimensions.width} ${dimensions.height}`}
          className="w-full h-auto"
          role="img"
          aria-label="Findings distribution radar chart"
        >
  // eslint-disable-next-line security/detect-object-injection
          {[0.25, 0.5, 0.75, 1].map((ratio) => (
            <circle
              key={ratio}
              cx={dimensions.centerX}
              cy={dimensions.centerY}
              r={dimensions.radius * ratio}
              fill="none"
              stroke="var(--line, #333)"
              strokeDasharray="4 5"
              opacity={0.45}
            />
          ))}

          {radarPoints.map((point) => (
            <line
              key={`${point.category}-axis`}
              x1={dimensions.centerX}
              y1={dimensions.centerY}
              x2={dimensions.centerX + Math.cos(point.angle) * dimensions.radius}
              y2={dimensions.centerY + Math.sin(point.angle) * dimensions.radius}
              stroke="var(--line, #333)"
              opacity={0.55}
            />
          ))}

          <path d={polygonPath} fill={RADAR_FILL} fillOpacity={0.2} stroke={RADAR_STROKE} strokeWidth={2.2} />

          {radarPoints.map((point) => {
            const isHovered = hoveredCategory === point.category;
            return (
              <g
                key={point.category}
                onMouseEnter={() => setHoveredCategory(point.category)}
                onMouseLeave={() => setHoveredCategory(null)}
              >
                <circle
                  cx={point.x}
                  cy={point.y}
                  r={isHovered ? 6 : 4.2}
                  fill={RADAR_DOT_FILL}
                  stroke="#fff"
                  strokeWidth={isHovered ? 1.2 : 0.8}
                />
                <text
                  x={point.labelX}
                  y={point.labelY}
                  textAnchor={point.labelX >= dimensions.centerX ? 'start' : 'end'}
                  fill="var(--muted, #888)"
                  fontSize={11}
                >
                  {point.category}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {hovered && (
        <div className="cyber-tooltip">
          <div className="cyber-tooltip-header">{hovered.category}</div>
          <div className="cyber-tooltip-body">
            <div className="cyber-tooltip-row">
              <span className="cyber-tooltip-dot" style={{ backgroundColor: RADAR_STROKE }} />
              <span className="cyber-tooltip-label">Findings:</span>
              <span className="cyber-tooltip-value">{hovered.count}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
});
