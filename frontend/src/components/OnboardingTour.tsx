import { useState, useEffect, useRef, useCallback } from 'react';
import { useDisplay } from '../context/DisplayContext';

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
    title: 'Findings',
    description: 'Review, filter, and manage security findings across all targets.',
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

export function useOnboardingTour() {
  const { display } = useDisplay();
  const [active, setActive] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const initialized = useRef(false);

  useEffect(() => {
    if (initialized.current) return;
    initialized.current = true;

    const seen = localStorage.getItem(STORAGE_KEY);
    if (!seen && !display.reduceMotion) {
      setActive(true);
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

  if (!active || !step) return null;

  return (
    <div className="onboarding-overlay" onClick={skip}>
      <div className="onboarding-card" onClick={e => e.stopPropagation()}>
        <div className="onboarding-header">
          <h3 className="onboarding-title">{step.title}</h3>
          <button className="onboarding-skip" onClick={skip}>Skip</button>
        </div>
        <p className="onboarding-description">{step.description}</p>
        <div className="onboarding-progress">
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
