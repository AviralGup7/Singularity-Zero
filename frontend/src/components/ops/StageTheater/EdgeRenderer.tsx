import { motion } from 'framer-motion';
import type { VisualState } from '@/lib/visualState';

interface EdgeRendererProps {
  links: Array<{ id: string; d: string; isFlowing: boolean; hasFailure: boolean }>;
  visualState: VisualState;
}

export function EdgeRenderer({ links, visualState }: EdgeRendererProps) {
  return (
    <>
      {links.map((link) => (
        <g key={link.id}>
          <path d={link.d} className="stage-theater-edge"
            stroke={link.hasFailure ? 'url(#stageTheaterFailure)' : 'url(#stageTheaterFlow)'} />
          {link.isFlowing && (
            <>
              <motion.path d={link.d} className="stage-theater-edge stage-theater-edge--active"
                stroke={link.hasFailure ? 'var(--bad, #ff5568)' : 'var(--accent, #37f6ff)'}
                initial={{ pathLength: 0, opacity: 0.4 }}
                animate={{ pathLength: 1, opacity: [0.5, 1, 0.5], strokeDashoffset: [0, -36] }}
                transition={{ duration: Math.max(0.55, 1.35 - visualState.flow * 0.65), repeat: Number.POSITIVE_INFINITY, ease: 'linear' }} />
              <g className="stage-theater-edge-particles">
                <circle r={2.8} className="stage-theater-edge-particle"
                  fill={link.hasFailure ? 'var(--bad, #ff5568)' : 'var(--accent, #37f6ff)'}>
                  <animateMotion path={link.d} dur={`${Math.max(0.85, 1.8 - visualState.flow * 0.9)}s`} repeatCount="indefinite" />
                </circle>
                <circle r={2.1} className="stage-theater-edge-particle stage-theater-edge-particle--secondary"
                  fill={link.hasFailure ? 'rgba(255, 85, 104, 0.75)' : 'rgba(87, 167, 255, 0.75)'}>
                  <animateMotion path={link.d} dur={`${Math.max(1.05, 2.2 - visualState.flow)}s`} begin="0.36s" repeatCount="indefinite" />
                </circle>
              </g>
            </>
          )}
        </g>
      ))}
      <defs>
        <linearGradient id="stageTheaterFlow" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="var(--accent, #37f6ff)" stopOpacity="0.35" />
          <stop offset="55%" stopColor="var(--accent, #37f6ff)" stopOpacity="0.95" />
          <stop offset="100%" stopColor="var(--accent-2, #57a7ff)" stopOpacity="0.35" />
        </linearGradient>
        <linearGradient id="stageTheaterFailure" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="var(--bad, #ff5568)" stopOpacity="0.25" />
          <stop offset="50%" stopColor="var(--bad, #ff5568)" stopOpacity="0.95" />
          <stop offset="100%" stopColor="var(--bad, #ff5568)" stopOpacity="0.25" />
        </linearGradient>
      </defs>
    </>
  );
}
