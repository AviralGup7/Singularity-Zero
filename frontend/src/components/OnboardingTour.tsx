import { useState, useEffect, useRef, useCallback } from 'react';
import { useDisplay } from '@/hooks/useDisplay';

interface TourStep {
  title: string;
  description: string;
  target?: string;
  path?: string;
}

const TOUR_STEPS: TourStep[] = [
  {
    title: 'Welcome to Cyber Security Test Pipeline',
    description: 'This tour will walk you through the main features of the application.',
  },
  {
    title: 'Dashboard',
    description: 'Get an overview of your security posture, active jobs, and findings at a glance.',
    target: '[data-tour="dashboard"]',
  },
  {
    title: 'Targets',
    description: 'Manage your scan targets and view findings organized by target.',
    target: '[data-tour="targets"]',
    path: '/targets',
  },
  {
    title: 'Jobs',
    description: 'Monitor running scans, view job details, and manage pipeline execution.',
    target: '[data-tour="jobs"]',
    path: '/jobs',
  },
  {
    title: 'Findings Triage',
    description: 'Switch the view mode to Table, then use the bulk action bar to change status, mark false positives, assign, or delete across many findings at once.',
    target: '[data-tour="findings"]',
    path: '/findings',
  },
  {
    title: 'Evidence & Chain of Custody',
    description: 'Open any finding detail, then look for the Evidence tab to inspect the request/response and the chain-of-custody record proving integrity.',
    target: '[data-tour="findings"]',
    path: '/findings',
  },
  {
    title: 'Reporting',
    description: 'Build a structured report from selected findings and export to Markdown, HTML, or JSON. Signed artefacts remain in the Reports library.',
    target: '[data-tour="findings"]',
    path: '/findings',
  },
  {
    title: 'Settings',
    description: 'Customize themes, display options, notifications, and more.',
    target: '[data-tour="settings"]',
    path: '/settings',
  },
];

const STORAGE_KEY = 'cyber-pipeline-onboarding-complete';

function useOnboardingTour() {
  const { display } = useDisplay();
   
  const [active, setActive] = useState(false);
   
  const [currentStep, setCurrentStep] = useState(0);
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    const seen = localStorage.getItem(STORAGE_KEY);
    if (!seen && !display.reduceMotion) {
      Promise.resolve().then(() => {
        setActive(true);
      });
    }
   
  }, [display.reduceMotion]);

  const next = useCallback(() => {
    if (currentStep < TOUR_STEPS.length - 1) {
   
      const step = TOUR_STEPS[currentStep + 1];
      setCurrentStep(s => s + 1);
      if (step.path && window.location.pathname !== step.path) {
        window.history.pushState({}, '', step.path);
      }
    } else {
      setActive(false);
      localStorage.setItem(STORAGE_KEY, 'true');
    }
   
  }, [currentStep]);

  const skip = useCallback(() => {
    setActive(false);
    localStorage.setItem(STORAGE_KEY, 'true');
  }, []);

  const prev = useCallback(() => {
    if (currentStep > 0) {
      setCurrentStep(s => s - 1);
    }
  }, [currentStep]);

  return {
    active,
    // eslint-disable-next-line security/detect-object-injection
    step: TOUR_STEPS[currentStep],
    currentStep,
    totalSteps: TOUR_STEPS.length,
    next,
    prev,
    skip,
  };
}

export function OnboardingTour() {
  const { active, step, currentStep, totalSteps, next, prev, skip } = useOnboardingTour();

  useEffect(() => {
    if (!active) return;
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') skip();
    };
    const handlePopState = () => {
      skip();
    };
    window.addEventListener('keydown', handleEsc);
    window.addEventListener('popstate', handlePopState);
    return () => {
      window.removeEventListener('keydown', handleEsc);
      window.removeEventListener('popstate', handlePopState);
    };
  }, [active, skip]);

  if (!active || !step) return null;

  return (
    // eslint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/no-static-element-interactions
    <div
      className="onboarding-overlay"
      onClick={(e) => {
        if (e.target === e.currentTarget) skip();
      }}
    >
      <div
        className="onboarding-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="tour-title"
        aria-describedby="tour-description"
      >
        <div className="onboarding-header">
          <h3 id="tour-title" className="onboarding-title">{step.title}</h3>
          <button className="onboarding-skip" onClick={skip} aria-label="Skip tour">Skip</button>
        </div>
        <p id="tour-description" className="onboarding-description">{step.description}</p>
        <div className="onboarding-progress" role="progressbar" aria-valuenow={currentStep + 1} aria-valuemin={1} aria-valuemax={totalSteps}>
          {Array.from({ length: totalSteps }).map((_, i) => (
            <span
              key={i}
              className={`onboarding-dot ${i === currentStep ? 'active' : i < currentStep ? 'done' : ''}`}
            />
          ))}
        </div>
        <div className="onboarding-actions">
          {currentStep > 0 && (
            <button className="btn btn-secondary" onClick={prev}>Previous</button>
          )}
          <button className="btn btn-primary" onClick={next}>
            {currentStep === totalSteps - 1 ? 'Get Started' : 'Next'}
          </button>
        </div>
      </div>
    </div>
  );
}
