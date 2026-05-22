import { useEffect, useRef } from 'react';
import { useMotionPolicy } from '@/hooks/useMotionPolicy';

interface CinematicIntroProps {
  className?: string;
  children: React.ReactNode;
}

interface GsapTimeline {
  kill: () => void;
  fromTo: (target: any, fromVars: object, toVars: object, position?: any) => GsapTimeline;
}

interface GsapInstance {
  timeline: (config?: { defaults?: { ease?: string } }) => GsapTimeline;
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
        const typedMod = mod as unknown as { gsap?: unknown; default?: unknown };
        const gsap = (typedMod.gsap ?? typedMod.default) as GsapInstance | undefined;
        if (!gsap) return;
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
