/**
 * Re-export the canonical `useGapAnalysisFiltering` from `useGapAnalysis.ts`
 * to avoid drift between two separate implementations with different APIs.
 */
export { useGapAnalysisFiltering, type StatusFilter } from './useGapAnalysis';
