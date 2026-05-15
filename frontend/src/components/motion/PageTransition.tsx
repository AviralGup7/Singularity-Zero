import { motion } from 'framer-motion';
import type { ReactNode } from 'react';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';

interface PageTransitionProps {
  children: ReactNode;
}

export function PageTransition({ children }: PageTransitionProps) {
  const { policy, strategy } = useMotionPolicy('page');

  if (policy.tier === 'static') {
    return <>{children}</>;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: strategy.distance }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -Math.min(10, strategy.distance) }}
      transition={{ duration: strategy.duration, ease: 'easeOut' }}
      className="page-transition"
    >
      {children}
    </motion.div>
  );
}
