import { type AppSettings } from '../../../context/SettingsContext';
import { SettingsSectionCard, SettingSelect, SettingToggle, SettingInput } from '../SettingsComponents';

interface ReportsSectionProps {
  reportFormat: AppSettings['reports']['format'];
  includeRawResponses: boolean;
  includeProofOfConcept: boolean;
  reportAutoSave: boolean;
  outputDirectory: string;
  onReportFormatChange: (v: string) => void;
  onIncludeRawResponsesChange: (v: boolean) => void;
  onIncludeProofOfConceptChange: (v: boolean) => void;
  onReportAutoSaveChange: (v: boolean) => void;
  onOutputDirectoryChange: (v: string) => void;
}

export function ReportsSection({ reportFormat, includeRawResponses, includeProofOfConcept, reportAutoSave, outputDirectory, onReportFormatChange, onIncludeRawResponsesChange, onIncludeProofOfConceptChange, onReportAutoSaveChange, onOutputDirectoryChange }: ReportsSectionProps) {
  return (
    <SettingsSectionCard title="Reports" icon="\ud83d\udcc4">
      <SettingSelect
        label="Format"
        value={reportFormat}
        onChange={onReportFormatChange}
        options={[{ label: 'Markdown', value: 'markdown' }, { label: 'HTML', value: 'html' }, { label: 'JSON', value: 'json' }, { label: 'PDF', value: 'pdf' }]}
        description="Default report format"
      />
      <SettingToggle label="Include Raw Responses" checked={includeRawResponses} onChange={onIncludeRawResponsesChange} description="Include raw HTTP responses in reports" />
      <SettingToggle label="Include Proof of Concept" checked={includeProofOfConcept} onChange={onIncludeProofOfConceptChange} description="Include PoC code snippets" />
      <SettingToggle label="Auto Save" checked={reportAutoSave} onChange={onReportAutoSaveChange} description="Automatically save reports to disk" />
      <SettingInput label="Output Directory" value={outputDirectory} onChange={onOutputDirectoryChange} placeholder="./reports" description="Default report output path" />
    </SettingsSectionCard>
  );
}
