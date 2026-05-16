import { SettingsSectionCard, SettingToggle } from '../SettingsComponents';

interface ExperimentalSectionProps {
  experimentalEnabled: boolean;
  behaviorAnalysis: boolean;
  attackValidation: boolean;
  graphIntelligence: boolean;
  polymorphicEvasion: boolean;
  antiForensicMode: boolean;
  onExperimentalEnabledChange: (v: boolean) => void;
  onBehaviorAnalysisChange: (v: boolean) => void;
  onAttackValidationChange: (v: boolean) => void;
  onGraphIntelligenceChange: (v: boolean) => void;
  onPolymorphicEvasionChange: (v: boolean) => void;
  onAntiForensicModeChange: (v: boolean) => void;
}

export function ExperimentalSection({ 
  experimentalEnabled, 
  behaviorAnalysis, 
  attackValidation, 
  graphIntelligence, 
  polymorphicEvasion,
  antiForensicMode,
  onExperimentalEnabledChange, 
  onBehaviorAnalysisChange, 
  onAttackValidationChange, 
  onGraphIntelligenceChange,
  onPolymorphicEvasionChange,
  onAntiForensicModeChange
}: ExperimentalSectionProps) {
  return (
    <SettingsSectionCard title="Experimental & Frontier" icon="🧪">
      <SettingToggle label="Enable Experimental Features" checked={experimentalEnabled} onChange={onExperimentalEnabledChange} description="Enable unstable and frontier protocols" />
      {experimentalEnabled && (
        <>
          <SettingToggle label="Behavior Analysis" checked={behaviorAnalysis} onChange={onBehaviorAnalysisChange} description="Analyze application behavior patterns" />
          <SettingToggle label="Attack Validation" checked={attackValidation} onChange={onAttackValidationChange} description="Validate findings with safe exploitation" />
          <SettingToggle label="Graph Intelligence" checked={graphIntelligence} onChange={onGraphIntelligenceChange} description="Use Kuzu graph-based analysis for kill-chains" />
          <div className="my-4 border-t border-white/5 pt-4">
             <h5 className="text-[10px] font-black text-accent uppercase tracking-widest mb-4">Neural-Mesh Frontier Protocols</h5>
             <SettingToggle label="Polymorphic Evasion" checked={polymorphicEvasion} onChange={onPolymorphicEvasionChange} description="Real-time request fingerprint mutation (WAF bypass)" />
             <SettingToggle label="Anti-Forensic Mode" checked={antiForensicMode} onChange={onAntiForensicModeChange} description="RAM-only Ghost-VFS storage (Zero persistent footprint)" />
          </div>
        </>
      )}
    </SettingsSectionCard>
  );
}

