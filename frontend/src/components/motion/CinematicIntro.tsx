import { useEffect, useRef } from 'react';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';

interface CinematicIntroProps {
  className?: string;
  children: React.ReactNode;
}

export function CinematicIntro({ className, children }: CinematicIntroProps) {
  const { policy, strategy } = useMotionPolicy('hero');
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!containerRef.current || !policy.allowGsap) {
      return;
    }
    let cancelled = false;
    let cleanup: (() => void) | undefined;

    void import('gsap')
      .then((mod) => {
        if (!containerRef.current || cancelled) return;
        const gsap = mod.gsap ?? mod.default;
        const tl = gsap.timeline({ defaults: { ease: 'power3.out' } });
        tl.fromTo(
          containerRef.current.querySelectorAll('[data-cinematic]'),
          { opacity: 0, y: strategy.distance, filter: 'blur(10px)' },
          {
            opacity: 1,
            y: 0,
            filter: 'blur(0px)',
            duration: strategy.duration,
            stagger: strategy.stagger,
          }
        );
        cleanup = () => tl.kill();
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
      cleanup?.();
    };
  }, [policy.allowGsap, strategy.distance, strategy.duration, strategy.stagger]);

  return (
    <div ref={containerRef} className={className}>
      {children}
    </div>
  );
}
