import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { ROUTES } from '@/config/paths';
import { useDisplay } from '@/hooks/useDisplay';
import { useDisplayStore } from '@/stores/displayStore';

interface TourStep {
  title: string;
  description: string;
  target?: string;
  path?: string;
}

const PENTEST_STEPS: TourStep[] = [
  {
    title: 'Welcome to Penetration Testing Pipeline',
    description: 'This tour covers the pentest-specific workflow: live terminal streams, 3D attack graphs, and real-time telemetry.',
  },
  {
    title: 'Dashboard',
    description: 'Monitor active penetration tests, live shell sessions, and real-time findings at a glance.',
    target: '[data-tour="dashboard"]',
  },
  {
    title: 'Targets',
    description: 'Manage in-scope targets and launch custom pentest modules.',
    target: '[data-tour="targets"]',
    path: ROUTES.TARGETS,
  },
  {
    title: 'Live Terminal',
    description: 'Stream real-time command output from remote agents during active exploitation.',
    target: '[data-tour="terminal"]',
    path: ROUTES.JOBS,
  },
  {
    title: '3D Attack Graph',
    description: 'Visualize the attack surface and pivot paths through an interactive 3D graph.',
    path: ROUTES.PIPELINE,
  },
  {
    title: 'Settings',
    description: 'Configure proxy chains, module triggers, and reporting preferences.',
    target: '[data-tour="settings"]',
    path: ROUTES.SETTINGS,
  },
];

const APP_SEC_STEPS: TourStep[] = [
  {
    title: 'Welcome to Application Security Pipeline',
    description: 'This tour covers the AppSec workflow: SAST, DAST, dependency scanning, and compliance tracking.',
  },
  {
    title: 'Dashboard',
    description: 'Get an overview of your security posture, active scans, and findings at a glance.',
    target: '[data-tour="dashboard"]',
  },
  {
    title: 'Targets',
    description: 'Manage your scan targets and view findings organized by application.',
    target: '[data-tour="targets"]',
    path: ROUTES.TARGETS,
  },
  {
    title: 'Jobs',
    description: 'Monitor running scans, view job details, and manage pipeline execution.',
    target: '[data-tour="jobs"]',
    path: ROUTES.JOBS,
  },
  {
    title: 'Findings Triage',
    description: 'Switch the view mode to Table, then use the bulk action bar to change status, mark false positives, assign, or delete across many findings at once.',
    target: '[data-tour="findings"]',
    path: ROUTES.FINDINGS,
  },
  {
    title: 'Evidence & Chain of Custody',
    description: 'Open any finding detail, then look for the Evidence tab to inspect the request/response and the chain-of-custody record proving integrity.',
    target: '[data-tour="findings"]',
    path: ROUTES.FINDINGS,
  },
  {
    title: 'Reporting',
    description: 'Build a structured report from selected findings and export to Markdown, HTML, or JSON. Signed artefacts remain in the Reports library.',
    target: '[data-tour="findings"]',
    path: ROUTES.FINDINGS,
  },
  {
    title: 'Settings',
    description: 'Customize themes, display options, notifications, and more.',
    target: '[data-tour="settings"]',
    path: ROUTES.SETTINGS,
  },
];

const STORAGE_KEY = 'cyber-pipeline-onboarding-complete';

function useOnboardingTour() {
  const { display } = useDisplay();
  const workflowMode = useDisplayStore((s) => s.workflowMode);
  const navigate = useNavigate();

  const [active, setActive] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const initialized = useRef(false);

  const steps = useMemo(() => workflowMode === 'pentest' ? PENTEST_STEPS : APP_SEC_STEPS, [workflowMode]);

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
    if (currentStep < steps.length - 1) {
      const step = steps[currentStep + 1];
      setCurrentStep(s => s + 1);
      if (step.path && window.location.pathname !== step.path) {
        navigate(step.path, { replace: true });
      }
    } else {
      setActive(false);
      localStorage.setItem(STORAGE_KEY, 'true');
    }
  }, [currentStep, steps, navigate]);

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
    step: steps[currentStep],
    currentStep,
    totalSteps: steps.length,
    next,
    prev,
    skip,
  };
}

export function OnboardingTour() {
  const workflowMode = useDisplayStore((s) => s.workflowMode);
  const { active, step, currentStep, totalSteps, next, prev, skip } = useOnboardingTour();

  useEffect(() => {
    if (!active) return;
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') skip();
    };
    window.addEventListener('keydown', handleEsc);
    return () => {
      window.removeEventListener('keydown', handleEsc);
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
              key={`dot-${i}`}
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
