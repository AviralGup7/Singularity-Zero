import { SettingsSectionCard, SettingSelect, SettingToggle, SettingNumberInput } from '../SettingsComponents';

const concurrencyOptions = [
  { label: '1', value: 1 },
  { label: '2', value: 2 },
  { label: '4', value: 4 },
  { label: '8', value: 8 },
  { label: '16', value: 16 },
];

const timeoutOptions = [
  { label: '30s', value: 30 },
  { label: '1m', value: 60 },
  { label: '5m', value: 300 },
  { label: '10m', value: 600 },
  { label: '30m', value: 1800 },
];

interface PipelineSectionProps {
  pipelineConcurrency: number;
  pipelineTimeout: number;
  pipelineMaxRetries: number;
  pipelineVerboseLogging: boolean;
  pipelineParallelModules: boolean;
  onPipelineConcurrencyChange: (v: number) => void;
  onPipelineTimeoutChange: (v: number) => void;
  onPipelineMaxRetriesChange: (v: number) => void;
  onPipelineVerboseLoggingChange: (v: boolean) => void;
  onPipelineParallelModulesChange: (v: boolean) => void;
}

export function PipelineSection({ pipelineConcurrency, pipelineTimeout, pipelineMaxRetries, pipelineVerboseLogging, pipelineParallelModules, onPipelineConcurrencyChange, onPipelineTimeoutChange, onPipelineMaxRetriesChange, onPipelineVerboseLoggingChange, onPipelineParallelModulesChange }: PipelineSectionProps) {
  return (
    <SettingsSectionCard title="Pipeline" icon="\u2699\ufe0f">
      <SettingSelect
        label="Concurrency"
        value={pipelineConcurrency}
        onChange={v => onPipelineConcurrencyChange(Number(v))}
        options={concurrencyOptions.map(o => ({ label: o.label, value: o.value }))}
        description="Number of parallel pipeline stages"
      />
      <SettingSelect
        label="Timeout"
        value={pipelineTimeout}
        onChange={v => onPipelineTimeoutChange(Number(v))}
        options={timeoutOptions.map(o => ({ label: o.label, value: o.value }))}
        description="Maximum time per pipeline run"
      />
      <SettingNumberInput label="Max Retries" value={pipelineMaxRetries} onChange={onPipelineMaxRetriesChange} min={0} max={10} description="Number of retries on failure" />
      <SettingToggle label="Verbose Logging" checked={pipelineVerboseLogging} onChange={onPipelineVerboseLoggingChange} description="Enable detailed pipeline logs" />
      <SettingToggle label="Parallel Modules" checked={pipelineParallelModules} onChange={onPipelineParallelModulesChange} description="Run modules in parallel when possible" />
    </SettingsSectionCard>
  );
}
