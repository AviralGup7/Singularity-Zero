import { useState } from 'react';
import { startJob } from '../../api/client';
import { checkToolAvailability } from '../../api/selfHealing';
import { useToast } from '../../hooks/useToast';
import { validateUrl } from '../../lib/utils';
import { useJobFormState } from './useJobFormState';
import { TargetStep } from './TargetStep';
import { ModulesStep } from './ModulesStep';
import { ConfigStep } from './ConfigStep';
import { ReviewStep } from './ReviewStep';

interface StartJobFormProps {
  onJobStarted?: (jobId: string) => void;
}

   
const STEPS = ['Target', 'Modules', 'Configuration', 'Review'];

export default function StartJobForm({ onJobStarted }: StartJobFormProps) {
   
  const [expanded, setExpanded] = useState(false);
   
  const [submitting, setSubmitting] = useState(false);
   
  const [baseUrlError, setBaseUrlError] = useState<string | null>(null);
   
  const [scopeTextError, setScopeTextError] = useState<string | null>(null);
   
  const [currentStep, setCurrentStep] = useState(0);
  const toast = useToast();

  const form = useJobFormState();

  const validateStep = (step: number): boolean => {
    if (step === 0) {
      if (!form.baseUrl.trim() && !form.scopeText.trim()) {
        setBaseUrlError('Enter a base URL or paste a scope block.');
        return false;
      }
      if (form.baseUrl.trim()) {
        const result = validateUrl(form.baseUrl);
        if (!result.valid) {
          setBaseUrlError(result.error || 'Invalid URL.');
          return false;
        }
      }
      setBaseUrlError(null);
      return true;
    }
    if (step === 1) {
      if (form.selectedModules.size === 0) {
        form.setError('Select at least one module.');
        return false;
      }
      return true;
    }
    return true;
  };

  const handleNext = () => {
    form.setError(null);
    if (validateStep(currentStep)) {
      setCurrentStep(prev => Math.min(prev + 1, STEPS.length - 1));
    }
  };

  const handleBack = () => {
    setCurrentStep(prev => Math.max(prev - 1, 0));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    form.setError(null);
    setBaseUrlError(null);
    setScopeTextError(null);

    let hasError = false;
    if (!form.baseUrl.trim() && !form.scopeText.trim()) {
      setBaseUrlError('Enter a base URL or paste a scope block.');
      hasError = true;
    } else if (form.baseUrl.trim()) {
      const urlResult = validateUrl(form.baseUrl);
      if (!urlResult.valid) {
        setBaseUrlError(urlResult.error || 'Invalid URL.');
        hasError = true;
      }
    }

    if (hasError) {
      form.setError('Please fix the errors below.');
      return;
    }

    setSubmitting(true);
    try {
      // Check tool availability before starting scan
      const selectedModuleList = Array.from(form.selectedModules);
      if (selectedModuleList.length > 0) {
        try {
          const toolCheck = await checkToolAvailability(selectedModuleList);
          if (!toolCheck.all_available) {
            const missingTools = Object.entries(toolCheck.tools)
              .filter(([, info]) => !info.available)
              .map(([name]) => name);
            toast.warning(`Some tools may not be installed: ${missingTools.join(', ')}. Scan may partially fail.`);
          }
          if (toolCheck.any_breaker_open) {
            const openBreakers = Object.entries(toolCheck.tools)
              .filter(([, info]) => info.circuit_breaker_open)
              .map(([name]) => name);
            toast.warning(`Circuit breaker open for: ${openBreakers.join(', ')}. These stages will be skipped.`);
          }
        } catch {
          // Tool availability check is non-blocking; proceed with scan
        }
      }

      const nonDefaultExec = Object.fromEntries(
        Object.entries(form.executionOptions).filter(([, v]) => v)
      );
      const nonEmptyOverrides = Object.fromEntries(
        Object.entries(form.runtimeOverrides)
          .filter(([, v]) => v.trim().length > 0)
          .map(([k, v]) => [k, v.trim()])
      );

      // Map analysis checks to runtime overrides
      const analysisOverrides: Record<string, string> = {};
      form.checkOptions.forEach(opt => {
          analysisOverrides[opt.name] = form.analysisChecks.has(opt.name) ? '1' : '0';
      });
      
      const combinedOverrides = { ...nonEmptyOverrides, ...analysisOverrides };
      
      const scope = form.scopeText.trim() || undefined;

   
      const allUrls = form.baseUrl.trim().split(/[,;\n]+/).map(u => u.trim()).filter(Boolean);
   
      const primaryUrl = allUrls[0] || '';
      const extraUrls = allUrls.slice(1).join('\n');
   
      const combinedScope = [extraUrls, scope].filter(Boolean).join('\n').trim() || undefined;

      const job = await startJob({
        base_url: primaryUrl,
        scope_text: combinedScope,
        mode: form.selectedMode,
        modules: Array.from(form.selectedModules),
        execution_options: nonDefaultExec,
        runtime_overrides: combinedOverrides,
      });

      toast.success(`Scan started: ${job.id}`);
      form.setBaseUrl('');
      form.setScopeText('');
      setCurrentStep(0);
      onJobStarted?.(job.id);
    } catch (err) {
      form.setError(err instanceof Error ? err.message : 'Failed to start job');
      toast.error(`Failed to start scan: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setSubmitting(false);
    }
  };

  if (form.loading) {
    return <div className="card loading">Loading configuration...</div>;
  }

  const currentConfig = {
    mode: form.selectedMode,
    modules: form.selectedModules,
    executionOptions: form.executionOptions,
    runtimeOverrides: form.runtimeOverrides,
  };

  return (
    <div className="section">
      <div
        className="section-title section-title-clickable"
        onClick={() => setExpanded(!expanded)}
        onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded(!expanded); } }}
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
      >
        <span>Start New Scan</span>
        <span className="text-md">{expanded ? '▼' : '▶'}</span>
      </div>

      {expanded && (
        <form onSubmit={handleSubmit} className="card card-padded">
          {form.error && <div className="banner error" role="alert">{form.error}</div>}

          <div className="wizard-progress">
            {STEPS.map((label, idx) => (
              <button
                key={label}
                type="button"
                className={`wizard-step-indicator ${idx === currentStep ? 'active' : ''} ${idx < currentStep ? 'completed' : ''}`}
                onClick={() => { if (idx < currentStep) setCurrentStep(idx); }}
              >
                <span className="wizard-step-number">{idx + 1}</span>
                <span className="wizard-step-label">{label}</span>
              </button>
            ))}
            <div className="wizard-progress-bar">
              <div className="wizard-progress-fill" style={{ width: `${(currentStep / (STEPS.length - 1)) * 100}%` }} />
            </div>
          </div>

          {currentStep === 0 && (
            <TargetStep
              baseUrl={form.baseUrl}
              scopeText={form.scopeText}
              onBaseUrlChange={form.setBaseUrl}
              onScopeTextChange={form.setScopeText}
              baseUrlError={baseUrlError}
              scopeTextError={scopeTextError}
              onBaseUrlError={setBaseUrlError}
              onScopeTextError={setScopeTextError}
            />
          )}

          {currentStep === 1 && (
            <ModulesStep
              selectedMode={form.selectedMode}
              modePresets={form.modePresets}
              selectedModules={form.selectedModules}
              moduleGroups={form.moduleGroups}
              moduleOptions={form.moduleOptions}
              depWarnings={form.depWarnings}
              onModeSelect={form.handleModeSelect}
              onToggleModule={form.toggleModule}
              onAutoResolve={form.handleAutoResolve}
            />
          )}

          {currentStep === 2 && (
            <ConfigStep
              selectedModules={form.selectedModules}
              executionOptions={form.executionOptions}
              runtimeOverrides={form.runtimeOverrides}
              moduleOptions={form.moduleOptions}
              currentConfig={currentConfig}
              onLoadPreset={form.handleLoadPreset}
              onToggleExecutionOption={form.toggleExecutionOption}
              onUpdateRuntimeOverride={form.updateRuntimeOverride}
              analysisChecks={form.analysisChecks}
              onUpdateAnalysisChecks={form.updateAnalysisChecks}
              checkOptions={form.checkOptions}
              controlGroups={form.controlGroups}
              focusPresets={form.focusPresets}
            />
          )}

          {currentStep === 3 && (
            <ReviewStep
              baseUrl={form.baseUrl}
              scopeText={form.scopeText}
              selectedMode={form.selectedMode}
              selectedModules={form.selectedModules}
              executionOptions={form.executionOptions}
              depWarnings={form.depWarnings}
            />
          )}

          <div className="flex gap-8 mt-16 wizard-nav">
            {currentStep > 0 && (
              <button type="button" className="btn btn-secondary btn-lg" onClick={handleBack}>
                Back
              </button>
            )}
            {currentStep < STEPS.length - 1 ? (
              <button type="button" className="btn btn-primary btn-lg" onClick={handleNext}>
                Next
              </button>
            ) : (
              <button type="submit" className="btn btn-primary btn-lg" disabled={submitting}>
                {submitting ? 'Starting...' : 'Start Scan'}
              </button>
            )}
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setExpanded(false)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
