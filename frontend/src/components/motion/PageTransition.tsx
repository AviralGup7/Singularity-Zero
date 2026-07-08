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
      initial={{ opacity: 0, y: strategy.distance, scale: 0.99 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, y: -Math.min(8, strategy.distance), scale: 0.99 }}
      transition={{ duration: strategy.duration, ease: [0.16, 1, 0.3, 1] }}
      className="page-transition"
      style={{ transformOrigin: 'top center' }}
    >
      {children}
    </motion.div>
  );
}
