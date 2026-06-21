/**
 * Charts feature module - public API
 * Only expose chart components needed by other features.
 * AttackChainGraph3D is lazy-loaded and should NOT be re-exported here
 * to avoid pulling Three.js into non-chart chunks.
 */
export { SeverityTrendChart } from '@/components/charts/SeverityTrendChart';
export { ModulePerformanceChart } from '@/components/charts/ModulePerformanceChart';
export { FindingsRadarChart } from '@/components/charts/FindingsRadarChart';
