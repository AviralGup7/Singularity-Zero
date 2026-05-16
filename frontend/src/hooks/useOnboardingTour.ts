import { useState, useEffect, useCallback, useRef } from 'react';

export interface OnboardingStep {
  id: string;
  title: string;
  description: string;
  target?: string;
  highlight?: string;
}

const DEFAULT_STEPS: OnboardingStep[] = [
  {
    id: 'welcome',
    title: 'Welcome to Cyber Pipeline',
    description: 'Your comprehensive security testing dashboard. Let us walk you through the key features.',
  },
  {
    id: 'dashboard',
    title: 'Dashboard',
    description: 'Monitor active jobs, completed targets, and total findings at a glance. Use quick links to navigate.',
    target: '.hero-stats',
  },
  {
    id: 'targets',
    title: 'Targets',
    description: 'Manage your scan targets, view findings, and track severity distribution across all targets.',
   
    target: '[href="/targets"]',
  },
  {
    id: 'jobs',
    title: 'Jobs',
    description: 'Launch new scans, monitor running jobs, and view detailed logs for each scan.',
   
    target: '[href="/jobs"]',
  },
  {
    id: 'findings',
    title: 'Findings',
    description: 'Review security findings, filter by severity, assign to team members, and track remediation.',
   
    target: '[href="/findings"]',
  },
  {
    id: 'shortcuts',
    title: 'Keyboard Shortcuts',
    description: 'Press ? anytime to see available keyboard shortcuts. Use Ctrl+K for quick search.',
  },
];

const STORAGE_KEY = 'cyber-pipeline-onboarding';

export function useOnboardingTour(steps: OnboardingStep[] = DEFAULT_STEPS) {
   
  const [isOpen, setIsOpen] = useState(false);
   
  const [currentStep, setCurrentStep] = useState(0);
   
  const [isComplete, setIsComplete] = useState(true);
  const highlightRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    let mounted = true;
    const initializeTour = async () => {
      try {
        const stored = localStorage.getItem(STORAGE_KEY);
        if (stored) {
          const parsed = JSON.parse(stored);
          if (parsed.completed) {
            if (mounted) setIsComplete(true);
            return;
          }
        }
        if (mounted) {
          setIsComplete(false);
          setIsOpen(true);
        }
      } catch {
        if (mounted) {
          setIsComplete(false);
          setIsOpen(true);
        }
      }
    };
    
    // Defer initialization to avoid synchronous state update in effect
    void initializeTour();
    
    return () => { mounted = false; };
  }, []);

  const current = steps[currentStep] || steps[0];

  useEffect(() => {
    if (!isOpen || !current?.target) {
      if (highlightRef.current) {
        highlightRef.current.remove();
        highlightRef.current = null;
      }
      return;
    }

    const el = document.querySelector(current.target);
    if (!el) return;

    if (!highlightRef.current) {
      const div = document.createElement('div');
      div.className = 'onboarding-highlight';
      div.style.cssText = `
        position: fixed;
        pointer-events: none;
        border: 2px solid var(--accent, #00f3ff);
        border-radius: 8px;
        box-shadow: 0 0 0 9999px rgba(0, 0, 0, 0.5), 0 0 20px var(--accent, #00f3ff);
        z-index: 10000;
        transition: all 0.3s ease;
      `;
      document.body.appendChild(div);
      highlightRef.current = div;
    }

    const rect = el.getBoundingClientRect();
    highlightRef.current.style.top = `${rect.top - 4}px`;
    highlightRef.current.style.left = `${rect.left - 4}px`;
    highlightRef.current.style.width = `${rect.width + 8}px`;
    highlightRef.current.style.height = `${rect.height + 8}px`;

    return () => {
      if (highlightRef.current) {
        highlightRef.current.remove();
        highlightRef.current = null;
      }
    };
   
  }, [isOpen, currentStep, current?.target]);

  const skip = useCallback(() => {
    setIsOpen(false);
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ completed: true }));
    setIsComplete(true);
    if (highlightRef.current) {
      highlightRef.current.remove();
      highlightRef.current = null;
    }
  }, []);

  const complete = useCallback(() => {
    setIsOpen(false);
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ completed: true }));
    setIsComplete(true);
    if (highlightRef.current) {
      highlightRef.current.remove();
      highlightRef.current = null;
    }
  }, []);

  const next = useCallback(() => {
    if (currentStep < steps.length - 1) {
      setCurrentStep(s => s + 1);
    } else {
      complete();
    }
   
  }, [currentStep, steps.length, complete]);

  const prev = useCallback(() => {
    if (currentStep > 0) {
      setCurrentStep(s => s - 1);
    }
   
  }, [currentStep]);

  const restart = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setCurrentStep(0);
    setIsOpen(true);
    setIsComplete(false);
  }, []);

  return {
    isOpen,
    currentStep,
    current,
    totalSteps: steps.length,
    progress: ((currentStep + 1) / steps.length) * 100,
    next,
    prev,
    skip,
    complete,
    restart,
    isComplete,
  };
}
