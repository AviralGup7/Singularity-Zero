import { useEffect } from 'react';
import { useAnimate } from 'framer-motion';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';

interface MicroPulseValueProps {
  value: string | number;
  className?: string;
}

export function MicroPulseValue({ value, className }: MicroPulseValueProps) {
   
  const [scope, animate] = useAnimate();
  const { policy } = useMotionPolicy('status');

  useEffect(() => {
    if (!policy.allowFramer || !scope.current) {
      return;
    }
    void animate(
      scope.current,
      {
   
        transform: ['scale(1)', 'scale(1.045)', 'scale(1)'],
   
        opacity: [1, 0.88, 1],
      },
      {
        duration: policy.tier === 'full' ? 0.28 : 0.18,
        ease: 'easeOut',
      }
    );
   
  }, [animate, policy.allowFramer, policy.tier, scope, value]);

  return (
    <span ref={scope} className={className}>
      {value}
    </span>
  );
}
