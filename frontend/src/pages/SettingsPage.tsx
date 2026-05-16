import {
  Palette, Monitor, LayoutDashboard, Bell, Shield, Settings as SettingsIcon,
  Link, FileText, Plug, Target, FlaskConical, Accessibility, Zap,
  ScrollText, TrafficCone, User, Keyboard, Database, Info, Globe,
} from 'lucide-react';
import { useTheme } from '@/hooks/useTheme';
import { useDisplay } from '@/hooks/useDisplay';
import { useSettings } from '@/hooks/useSettings'; import type { AppSettings } from '@/context/SettingsContext';
import { useState, useRef, useEffect, useMemo, useCallback } from 'react';
import { ConfirmDialog } from '../components/ui/ConfirmDialog';
import { Breadcrumbs } from '../components/ui/Breadcrumbs';
import { useAutoBreadcrumbs } from '../hooks/useAutoBreadcrumbs';
import { SettingsSectionCard } from '../components/settings/SettingsComponents';
import { UserProfileSection } from '../components/settings/UserProfileSection';
import {
  ThemeSection,
  DisplaySection,
  AccessibilitySection,
  DashboardSection,
  NotificationsSection,
  SecuritySection,
  PipelineSection,
  ApiSection,
  ReportsSection,
  IntegrationsSection,
  ScanProfilesSection,
  ExperimentalSection,
  PerformanceSection,
  ShortcutsSection,
  DataSection,
  AboutSection,
  LanguageSection,
} from '../components/settings/sections';

type SettingsSection = 'theme' | 'display' | 'dashboard' | 'notifications' | 'security' | 'pipeline' | 'api' | 'reports' | 'integrations' | 'scanProfiles' | 'experimental' | 'accessibility' | 'performance' | 'logging' | 'rateLimiting' | 'profiles' | 'shortcuts' | 'data' | 'about' | 'language';

type SettingsTab = 'appearance' | 'dashboard' | 'pipeline' | 'advanced' | 'data';

   
const settingsTabs: { id: SettingsTab; label: string; icon: React.ReactNode; sections: SettingsSection[] }[] = [
   
  { id: 'appearance', label: 'Appearance', icon: <Palette size={18} />, sections: ['theme', 'display', 'language', 'accessibility'] },
   
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} />, sections: ['dashboard', 'notifications'] },
   
  { id: 'pipeline', label: 'Pipeline', icon: <SettingsIcon size={18} />, sections: ['pipeline', 'api', 'security'] },
   
  { id: 'advanced', label: 'Advanced', icon: <Zap size={18} />, sections: ['reports', 'integrations', 'scanProfiles', 'experimental', 'performance', 'logging', 'rateLimiting', 'profiles', 'shortcuts'] },
   
  { id: 'data', label: 'Data', icon: <Database size={18} />, sections: ['data', 'about'] },
];

interface SettingsNavItem {
  id: SettingsSection;
  label: string;
  icon: React.ReactNode;
}

const settingsNavItems: SettingsNavItem[] = [
  { id: 'theme', label: 'Theme', icon: <Palette size={18} /> },
  { id: 'display', label: 'Display', icon: <Monitor size={18} /> },
  { id: 'language', label: 'Language', icon: <Globe size={18} /> },
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { id: 'notifications', label: 'Notifications', icon: <Bell size={18} /> },
  { id: 'security', label: 'Security', icon: <Shield size={18} /> },
  { id: 'pipeline', label: 'Pipeline', icon: <SettingsIcon size={18} /> },
  { id: 'api', label: 'API', icon: <Link size={18} /> },
  { id: 'reports', label: 'Reports', icon: <FileText size={18} /> },
  { id: 'integrations', label: 'Integrations', icon: <Plug size={18} /> },
  { id: 'scanProfiles', label: 'Scan Profiles', icon: <Target size={18} /> },
  { id: 'experimental', label: 'Experimental', icon: <FlaskConical size={18} /> },
  { id: 'accessibility', label: 'Accessibility', icon: <Accessibility size={18} /> },
  { id: 'performance', label: 'Performance', icon: <Zap size={18} /> },
  { id: 'logging', label: 'Logging', icon: <ScrollText size={18} /> },
  { id: 'rateLimiting', label: 'Rate Limiting', icon: <TrafficCone size={18} /> },
  { id: 'profiles', label: 'Profiles', icon: <User size={18} /> },
  { id: 'shortcuts', label: 'Shortcuts', icon: <Keyboard size={18} /> },
  { id: 'data', label: 'Data', icon: <Database size={18} /> },
  { id: 'about', label: 'About', icon: <Info size={18} /> },
];

export function SettingsPage() {
  const { theme, updater: themeUpdater } = useTheme();
  const { display, updater: displayUpdater } = useDisplay();
  const { settings, updater: settingsUpdater } = useSettings();
  const { updateSection } = settingsUpdater;

  const setThemeMode = themeUpdater.setThemeMode;
  const setAccentColor = themeUpdater.setAccentColor;
  const setMotionIntensity = themeUpdater.setMotionIntensity;
  const setEffectCapability = themeUpdater.setEffectCapability;
  const setDensity = displayUpdater.setDensity;
  const setFontSize = displayUpdater.setFontSize;
  const setAnimations = displayUpdater.setAnimations;
  const setGridBackground = displayUpdater.setGridBackground;
  
   
  const setAutoRefresh = useCallback((v: boolean) => updateSection('dashboard', { autoRefresh: v }), [updateSection]);
   
  const setRefreshInterval = useCallback((v: number) => updateSection('dashboard', { refreshInterval: v }), [updateSection]);
   
  const setJobCompleteNotification = useCallback((v: boolean) => updateSection('notifications', { jobComplete: v }), [updateSection]);
   
  const setJobFailedNotification = useCallback((v: boolean) => updateSection('notifications', { jobFailed: v }), [updateSection]);
   
  const setCriticalFindingsNotification = useCallback((v: boolean) => updateSection('notifications', { criticalFindings: v }), [updateSection]);
   
  const setSoundEnabled = useCallback((v: boolean) => updateSection('notifications', { soundEnabled: v }), [updateSection]);
   
  const setConfirmDestructiveActions = useCallback((v: boolean) => updateSection('security', { confirmDestructiveActions: v }), [updateSection]);
   
  const setShowSensitiveData = useCallback((v: boolean) => updateSection('security', { showSensitiveData: v }), [updateSection]);
   
  const setAutoLogoutMinutes = useCallback((v: number) => updateSection('security', { autoLogoutMinutes: v }), [updateSection]);
   
  const setPipelineConcurrency = useCallback((v: number) => updateSection('pipeline', { concurrency: v }), [updateSection]);
   
  const setPipelineTimeout = useCallback((v: number) => updateSection('pipeline', { timeout: v }), [updateSection]);
   
  const setPipelineMaxRetries = useCallback((v: number) => updateSection('pipeline', { maxRetries: v }), [updateSection]);
   
  const setPipelineVerboseLogging = useCallback((v: boolean) => updateSection('pipeline', { verboseLogging: v }), [updateSection]);
   
  const setPipelineParallelModules = useCallback((v: boolean) => updateSection('pipeline', { parallelModules: v }), [updateSection]);
   
  const setApiBaseUrl = useCallback((v: string) => updateSection('api', { baseUrl: v }), [updateSection]);
   
  const setApiTimeout = useCallback((v: number) => updateSection('api', { timeout: v }), [updateSection]);
   
  const setApiKey = useCallback((v: string) => updateSection('api', { apiKey: v }), [updateSection]);
   
  const setReportFormat = useCallback((v: string) => updateSection('reports', { format: v as AppSettings['reports']['format'] }), [updateSection]);
   
  const setIncludeRawResponses = useCallback((v: boolean) => updateSection('reports', { includeRawResponses: v }), [updateSection]);
   
  const setIncludeProofOfConcept = useCallback((v: boolean) => updateSection('reports', { includeProofOfConcept: v }), [updateSection]);
   
  const setReportAutoSave = useCallback((v: boolean) => updateSection('reports', { autoSave: v }), [updateSection]);
   
  const setOutputDirectory = useCallback((v: string) => updateSection('reports', { outputDirectory: v }), [updateSection]);
   
  const setWebhookUrl = useCallback((v: string) => updateSection('integrations', { webhookUrl: v }), [updateSection]);
   
  const setWebhookOnJobComplete = useCallback((v: boolean) => updateSection('integrations', { webhookOnJobComplete: v }), [updateSection]);
   
  const setWebhookOnCriticalFinding = useCallback((v: boolean) => updateSection('integrations', { webhookOnCriticalFinding: v }), [updateSection]);
   
  const setEmailNotifications = useCallback((v: boolean) => updateSection('integrations', { emailNotifications: v }), [updateSection]);
   
  const setEmailRecipient = useCallback((v: string) => updateSection('integrations', { emailRecipient: v }), [updateSection]);
   
  const setSlackWebhook = useCallback((v: string) => updateSection('integrations', { slackWebhook: v }), [updateSection]);
   
  const setDefaultScanProfile = useCallback((v: string) => updateSection('scanProfiles', { defaultProfile: v as AppSettings['scanProfiles']['defaultProfile'] }), [updateSection]);
   
  const setIncludeNuclei = useCallback((v: boolean) => updateSection('scanProfiles', { includeNuclei: v }), [updateSection]);
   
  const setIncludePassiveAnalysis = useCallback((v: boolean) => updateSection('scanProfiles', { includePassiveAnalysis: v }), [updateSection]);
   
  const setIncludeActiveProbes = useCallback((v: boolean) => updateSection('scanProfiles', { includeActiveProbes: v }), [updateSection]);
   
  const setIncludeIntelligence = useCallback((v: boolean) => updateSection('scanProfiles', { includeIntelligence: v }), [updateSection]);
   
  const setExperimentalEnabled = useCallback((v: boolean) => updateSection('experimental', { enabled: v }), [updateSection]);
   
  const setBehaviorAnalysis = useCallback((v: boolean) => updateSection('experimental', { behaviorAnalysis: v }), [updateSection]);
   
  const setAttackValidation = useCallback((v: boolean) => updateSection('experimental', { attackValidation: v }), [updateSection]);
   
  const setGraphIntelligence = useCallback((v: boolean) => updateSection('experimental', { graphIntelligence: v }), [updateSection]);
   
  const setPolymorphicEvasion = useCallback((v: boolean) => updateSection('experimental', { polymorphicEvasion: v }), [updateSection]);
   
  const setAntiForensicMode = useCallback((v: boolean) => updateSection('experimental', { antiForensicMode: v }), [updateSection]);
  
  const setReduceMotion = displayUpdater.setReduceMotion;
  const setHighContrast = displayUpdater.setHighContrast;
  const setFocusIndicators = displayUpdater.setFocusIndicators;
  const setScreenReaderOptimizations = displayUpdater.setScreenReaderOptimizations;
  
   
  const setEnableCaching = useCallback((v: boolean) => updateSection('performance', { enableCaching: v }), [updateSection]);
   
  const setCacheDuration = useCallback((v: number) => updateSection('performance', { cacheDuration: v }), [updateSection]);
   
  const setLazyLoadModules = useCallback((v: boolean) => updateSection('performance', { lazyLoadModules: v }), [updateSection]);
   
  const setMaxConcurrentRequests = useCallback((v: number) => updateSection('performance', { maxConcurrentRequests: v }), [updateSection]);
   
  const setToggleThemeShortcut = useCallback((v: string) => updateSection('shortcuts', { toggleTheme: v }), [updateSection]);
   
  const setOpenSettingsShortcut = useCallback((v: string) => updateSection('shortcuts', { openSettings: v }), [updateSection]);
   
  const setRefreshDashboardShortcut = useCallback((v: string) => updateSection('shortcuts', { refreshDashboard: v }), [updateSection]);
   
  const setQuickScanShortcut = useCallback((v: string) => updateSection('shortcuts', { quickScan: v }), [updateSection]);

  const resetToDefaults = settingsUpdater.resetToDefaults;
  const exportSettings = settingsUpdater.exportSettings;
  const importSettings = settingsUpdater.importSettings;

   
  const [showConfirmReset, setShowConfirmReset] = useState(false);
   
  const [importError, setImportError] = useState<string | null>(null);
   
  const [saveConfirmation, setSaveConfirmation] = useState<string | null>(null);
   
  const [activeTab, setActiveTab] = useState<SettingsTab>('appearance');
   
  const [activeSection, setActiveSection] = useState<SettingsSection>('theme');
   
  const [searchQuery, setSearchQuery] = useState('');
  const sectionRefs = useRef<Record<string, HTMLElement | null>>({});
  const saveTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Throttled scroll handler
  useEffect(() => {
    let ticking = false;
    const handleScroll = () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        const scrollPosition = window.scrollY + 100;
        for (const item of settingsNavItems) {
   
          const element = sectionRefs.current[item.id];
          if (element) {
            const { offsetTop, offsetHeight } = element;
            if (scrollPosition >= offsetTop && scrollPosition < offsetTop + offsetHeight) {
              setActiveSection(item.id);
              break;
            }
          }
        }
        ticking = false;
      });
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const scrollToSection = useCallback((sectionId: SettingsSection) => {
    const element = sectionRefs.current[sectionId];
    if (element) {
      element.scrollIntoView({ behavior: 'smooth', block: 'start' });
      setActiveSection(sectionId);
    }
  }, []);

  const handleExport = useCallback(() => {
    try {
      const json = exportSettings();
   
      const blob = new Blob([json], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'cyber-pipeline-settings.json';
      a.click();
      URL.revokeObjectURL(url);
      setSaveConfirmation('Settings exported successfully');
      if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
      saveTimeoutRef.current = setTimeout(() => setSaveConfirmation(null), 3000);
    } catch {
      setSaveConfirmation('Failed to export settings');
      if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
      saveTimeoutRef.current = setTimeout(() => setSaveConfirmation(null), 3000);
    }
   
  }, [exportSettings]);

  const handleImport = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
   
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const content = event.target?.result as string;
        const parsed = JSON.parse(content);
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          throw new Error('Invalid format');
        }
   
        const knownKeys = ['dashboard', 'notifications', 'security', 'pipeline', 'api', 'reports', 'integrations', 'scanProfiles', 'experimental', 'performance', 'shortcuts', 'profiles', 'logging', 'rateLimiting'];
        const hasKnownKey = knownKeys.some(k => k in parsed);
        if (!hasKnownKey) {
          throw new Error('Unrecognized settings format');
        }
        importSettings(parsed as Partial<AppSettings>);
        setImportError(null);
        setSaveConfirmation('Settings imported successfully');
        if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
        saveTimeoutRef.current = setTimeout(() => setSaveConfirmation(null), 3000);
      } catch {
        setImportError('Invalid settings file. Please check the file format.');
      }
    };
    reader.readAsText(file);
    e.target.value = '';
   
  }, [importSettings]);

  const handleReset = useCallback(() => {
    resetToDefaults();
    setShowConfirmReset(false);
    setImportError(null);
    setSaveConfirmation('Settings reset to defaults');
    if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
    saveTimeoutRef.current = setTimeout(() => setSaveConfirmation(null), 3000);
   
  }, [resetToDefaults]);

  const visibleSections = useMemo(() => {
    return settingsTabs.find(t => t.id === activeTab)?.sections ?? [];
   
  }, [activeTab]);

  const shouldShowSection = useCallback((sectionId: SettingsSection): boolean => {
    const inCurrentTab = visibleSections.includes(sectionId);
    if (!inCurrentTab) return false;
    if (!searchQuery) return true;
    const navItem = settingsNavItems.find(n => n.id === sectionId);
    return navItem ? (navItem.label + ' ' + sectionId).toLowerCase().includes(searchQuery.toLowerCase()) : false;
   
  }, [visibleSections, searchQuery]);

  const sectionRenderers = useMemo<Record<SettingsSection, React.ReactNode>>(() => ({
    theme: <ThemeSection themeMode={theme.mode} accentColor={theme.accentColor} onThemeModeChange={setThemeMode} onAccentColorChange={setAccentColor} />,
    display: <DisplaySection density={display.density} fontSize={display.fontSize} animations={display.animations} gridBackground={display.gridBackground} motionIntensity={theme.motionIntensity} effectCapability={theme.effectCapability} onDensityChange={setDensity} onFontSizeChange={setFontSize} onAnimationsChange={setAnimations} onGridBackgroundChange={setGridBackground} onMotionIntensityChange={setMotionIntensity} onEffectCapabilityChange={setEffectCapability} />,
    accessibility: <AccessibilitySection reduceMotion={display.reduceMotion} highContrast={display.highContrast} focusIndicators={display.focusIndicators} screenReaderOptimizations={display.screenReaderOptimizations} onReduceMotionChange={setReduceMotion} onHighContrastChange={setHighContrast} onFocusIndicatorsChange={setFocusIndicators} onScreenReaderOptimizationsChange={setScreenReaderOptimizations} />,
    language: <LanguageSection />,
    dashboard: <DashboardSection autoRefresh={settings.dashboard.autoRefresh} refreshInterval={settings.dashboard.refreshInterval} onAutoRefreshChange={setAutoRefresh} onRefreshIntervalChange={setRefreshInterval} />,
    notifications: <NotificationsSection jobCompleteNotification={settings.notifications.jobComplete} jobFailedNotification={settings.notifications.jobFailed} criticalFindingsNotification={settings.notifications.criticalFindings} soundEnabled={settings.notifications.soundEnabled} onJobCompleteNotificationChange={setJobCompleteNotification} onJobFailedNotificationChange={setJobFailedNotification} onCriticalFindingsNotificationChange={setCriticalFindingsNotification} onSoundEnabledChange={setSoundEnabled} />,
    security: <SecuritySection confirmDestructiveActions={settings.security.confirmDestructiveActions} showSensitiveData={settings.security.showSensitiveData} autoLogoutMinutes={settings.security.autoLogoutMinutes} onConfirmDestructiveActionsChange={setConfirmDestructiveActions} onShowSensitiveDataChange={setShowSensitiveData} onAutoLogoutMinutesChange={setAutoLogoutMinutes} />,
    pipeline: <PipelineSection pipelineConcurrency={settings.pipeline.concurrency} pipelineTimeout={settings.pipeline.timeout} pipelineMaxRetries={settings.pipeline.maxRetries} pipelineVerboseLogging={settings.pipeline.verboseLogging} pipelineParallelModules={settings.pipeline.parallelModules} onPipelineConcurrencyChange={setPipelineConcurrency} onPipelineTimeoutChange={setPipelineTimeout} onPipelineMaxRetriesChange={setPipelineMaxRetries} onPipelineVerboseLoggingChange={setPipelineVerboseLogging} onPipelineParallelModulesChange={setPipelineParallelModules} />,
    api: <ApiSection apiBaseUrl={settings.api.baseUrl} apiTimeout={settings.api.timeout} apiKey={settings.api.apiKey} onApiBaseUrlChange={setApiBaseUrl} onApiTimeoutChange={setApiTimeout} onApiKeyChange={setApiKey} />,
    reports: <ReportsSection reportFormat={settings.reports.format} includeRawResponses={settings.reports.includeRawResponses} includeProofOfConcept={settings.reports.includeProofOfConcept} reportAutoSave={settings.reports.autoSave} outputDirectory={settings.reports.outputDirectory} onReportFormatChange={setReportFormat} onIncludeRawResponsesChange={setIncludeRawResponses} onIncludeProofOfConceptChange={setIncludeProofOfConcept} onReportAutoSaveChange={setReportAutoSave} onOutputDirectoryChange={setOutputDirectory} />,
    integrations: <IntegrationsSection webhookUrl={settings.integrations.webhookUrl} webhookOnJobComplete={settings.integrations.webhookOnJobComplete} webhookOnCriticalFinding={settings.integrations.webhookOnCriticalFinding} emailNotifications={settings.integrations.emailNotifications} emailRecipient={settings.integrations.emailRecipient} slackWebhook={settings.integrations.slackWebhook} onWebhookUrlChange={setWebhookUrl} onWebhookOnJobCompleteChange={setWebhookOnJobComplete} onWebhookOnCriticalFindingChange={setWebhookOnCriticalFinding} onEmailNotificationsChange={setEmailNotifications} onEmailRecipientChange={setEmailRecipient} onSlackWebhookChange={setSlackWebhook} />,
    scanProfiles: <ScanProfilesSection defaultScanProfile={settings.scanProfiles.defaultProfile} includeNuclei={settings.scanProfiles.includeNuclei} includePassiveAnalysis={settings.scanProfiles.includePassiveAnalysis} includeActiveProbes={settings.scanProfiles.includeActiveProbes} includeIntelligence={settings.scanProfiles.includeIntelligence} onDefaultScanProfileChange={setDefaultScanProfile} onIncludeNucleiChange={setIncludeNuclei} onIncludePassiveAnalysisChange={setIncludePassiveAnalysis} onIncludeActiveProbesChange={setIncludeActiveProbes} onIncludeIntelligenceChange={setIncludeIntelligence} />,
    experimental: <ExperimentalSection experimentalEnabled={settings.experimental.enabled} behaviorAnalysis={settings.experimental.behaviorAnalysis} attackValidation={settings.experimental.attackValidation} graphIntelligence={settings.experimental.graphIntelligence} polymorphicEvasion={settings.experimental.polymorphicEvasion} antiForensicMode={settings.experimental.antiForensicMode} onExperimentalEnabledChange={setExperimentalEnabled} onBehaviorAnalysisChange={setBehaviorAnalysis} onAttackValidationChange={setAttackValidation} onGraphIntelligenceChange={setGraphIntelligence} onPolymorphicEvasionChange={setPolymorphicEvasion} onAntiForensicModeChange={setAntiForensicMode} />,
    performance: <PerformanceSection enableCaching={settings.performance.enableCaching} cacheDuration={settings.performance.cacheDuration} lazyLoadModules={settings.performance.lazyLoadModules} maxConcurrentRequests={settings.performance.maxConcurrentRequests} onEnableCachingChange={setEnableCaching} onCacheDurationChange={setCacheDuration} onLazyLoadModulesChange={setLazyLoadModules} onMaxConcurrentRequestsChange={setMaxConcurrentRequests} />,
    logging: <SettingsSectionCard title="Logging" icon="📝"><p>Logging settings are configured via environment variables.</p></SettingsSectionCard>,
    rateLimiting: <SettingsSectionCard title="Rate Limiting" icon="🚧"><p>Rate limiting is managed by the backend.</p></SettingsSectionCard>,
    profiles: <UserProfileSection />,
    shortcuts: <ShortcutsSection toggleThemeShortcut={settings.shortcuts.toggleTheme} openSettingsShortcut={settings.shortcuts.openSettings} refreshDashboardShortcut={settings.shortcuts.refreshDashboard} quickScanShortcut={settings.shortcuts.quickScan} onToggleThemeShortcutChange={setToggleThemeShortcut} onOpenSettingsShortcutChange={setOpenSettingsShortcut} onRefreshDashboardShortcutChange={setRefreshDashboardShortcut} onQuickScanShortcutChange={setQuickScanShortcut} />,
    data: <DataSection onExport={handleExport} onImport={handleImport} onReset={handleReset} importError={importError} saveConfirmation={saveConfirmation} />,
    about: <AboutSection />,
  }), [
    theme.mode, theme.accentColor, theme.motionIntensity, theme.effectCapability, 
    display.density, display.fontSize, display.animations, display.gridBackground, display.reduceMotion, display.highContrast, display.focusIndicators, display.screenReaderOptimizations,
    settings, handleExport, handleImport, handleReset, importError, saveConfirmation,
    setThemeMode, setAccentColor, setMotionIntensity, setEffectCapability,
    setDensity, setFontSize, setAnimations, setGridBackground, setReduceMotion, setHighContrast, setFocusIndicators, setScreenReaderOptimizations,
    setAutoRefresh, setRefreshInterval, setJobCompleteNotification, setJobFailedNotification, setCriticalFindingsNotification, setSoundEnabled, setConfirmDestructiveActions, setShowSensitiveData, setAutoLogoutMinutes,
    setPipelineConcurrency, setPipelineTimeout, setPipelineMaxRetries, setPipelineVerboseLogging, setPipelineParallelModules,
    setApiBaseUrl, setApiTimeout, setApiKey, setReportFormat, setIncludeRawResponses, setIncludeProofOfConcept, setReportAutoSave, setOutputDirectory,
    setWebhookUrl, setWebhookOnJobComplete, setWebhookOnCriticalFinding, setEmailNotifications, setEmailRecipient, setSlackWebhook,
    setDefaultScanProfile, setIncludeNuclei, setIncludePassiveAnalysis, setIncludeActiveProbes, setIncludeIntelligence,
    setExperimentalEnabled, setBehaviorAnalysis, setAttackValidation, setGraphIntelligence, setPolymorphicEvasion, setAntiForensicMode,
    setEnableCaching, setCacheDuration, setLazyLoadModules, setMaxConcurrentRequests,
    setToggleThemeShortcut, setOpenSettingsShortcut, setRefreshDashboardShortcut, setQuickScanShortcut
  ]);

  useEffect(() => {
    return () => {
      if (saveTimeoutRef.current) clearTimeout(saveTimeoutRef.current);
    };
  }, []);

  const crumbs = useAutoBreadcrumbs();

  return (
    <div className="settings-page">
      <Breadcrumbs items={crumbs} />
      <div className="page-header">
        <h2 data-focus-heading>⚙️ Settings</h2>
      </div>

      {saveConfirmation && <div className="banner ok" role="status">{saveConfirmation}</div>}

      <div className="settings-tabs" role="tablist" aria-label="Settings categories">
        {settingsTabs.map(tab => (
          <button
            key={tab.id}
            id={`settings-tab-${tab.id}`}
            type="button"
            role="tab"
            aria-selected={activeTab === tab.id}
            aria-controls={`settings-panel-${tab.id}`}
            className={`settings-tab ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <span className="tab-icon">{tab.icon}</span>
            <span className="tab-label">{tab.label}</span>
          </button>
        ))}
      </div>

      <div className="settings-search">
        <label htmlFor="settings-search" className="sr-only">Search settings</label>
        <input
          id="settings-search"
          type="search"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          className="settings-search-input"
          placeholder="🔍 Search settings..."
          aria-label="Search settings"
        />
        {searchQuery && (
          <button type="button" className="search-clear-btn" onClick={() => setSearchQuery('')} aria-label="Clear search">
            ×
          </button>
        )}
      </div>

      <div className="settings-layout">
        <nav className="settings-nav" aria-label="Settings sections">
          {settingsNavItems
            .filter(item => shouldShowSection(item.id))
            .map(item => (
              <button
                key={item.id}
                type="button"
                className={`settings-nav-item ${activeSection === item.id ? 'active' : ''}`}
                onClick={() => scrollToSection(item.id)}
              >
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </button>
            ))}
        </nav>

        <div className="settings-content" id={`settings-panel-${activeTab}`} role="tabpanel" aria-labelledby={`settings-tab-${activeTab}`}>
          {visibleSections
            .filter(id => shouldShowSection(id))
            .map(sectionId => (
              <div
                key={sectionId}
                ref={el => { sectionRefs.current[sectionId] = el; }}
                className="settings-section"
              >
                {sectionRenderers[sectionId]}
              </div>
            ))}
        </div>
      </div>

      <ConfirmDialog
        isOpen={showConfirmReset}
        title="Reset to Defaults"
        message="Are you sure you want to reset all settings to their default values? This cannot be undone."
        confirmText="Reset"
        onConfirm={handleReset}
        onCancel={() => setShowConfirmReset(false)}
        variant="danger"
      />
    </div>
  );
}
