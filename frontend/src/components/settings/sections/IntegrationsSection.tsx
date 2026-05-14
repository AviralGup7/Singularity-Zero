import { useState } from 'react';
import { SettingsSectionCard, SettingToggle, SettingInput } from '../SettingsComponents';

interface IntegrationsSectionProps {
  webhookUrl: string;
  webhookOnJobComplete: boolean;
  webhookOnCriticalFinding: boolean;
  emailNotifications: boolean;
  emailRecipient: string;
  slackWebhook: string;
  onWebhookUrlChange: (v: string) => void;
  onWebhookOnJobCompleteChange: (v: boolean) => void;
  onWebhookOnCriticalFindingChange: (v: boolean) => void;
  onEmailNotificationsChange: (v: boolean) => void;
  onEmailRecipientChange: (v: string) => void;
  onSlackWebhookChange: (v: string) => void;
}

export function IntegrationsSection({ webhookUrl, webhookOnJobComplete, webhookOnCriticalFinding, emailNotifications, emailRecipient, slackWebhook, onWebhookUrlChange, onWebhookOnJobCompleteChange, onWebhookOnCriticalFindingChange, onEmailNotificationsChange, onEmailRecipientChange, onSlackWebhookChange }: IntegrationsSectionProps) {
  const [showWebhookUrl, setShowWebhookUrl] = useState(false);
  const [showSlackWebhook, setShowSlackWebhook] = useState(false);

  return (
    <SettingsSectionCard title="Integrations" icon="\ud83d\udd0c">
      <div className="setting-input-row">
        <div className="setting-label">
          <span className="setting-title">Webhook URL</span>
          <span className="setting-desc">Send events to external service</span>
        </div>
        <div className="setting-input-with-toggle">
          <input type={showWebhookUrl ? 'text' : 'password'} value={webhookUrl} onChange={e => onWebhookUrlChange(e.target.value)} placeholder="https://hooks.example.com/..." className="setting-input" />
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setShowWebhookUrl(!showWebhookUrl)} aria-label={showWebhookUrl ? 'Hide webhook URL' : 'Show webhook URL'}>
            {showWebhookUrl ? 'Hide' : 'Show'}
          </button>
        </div>
      </div>
      <SettingToggle label="On Job Complete" checked={webhookOnJobComplete} onChange={onWebhookOnJobCompleteChange} description="Send webhook on job completion" />
      <SettingToggle label="On Critical Finding" checked={webhookOnCriticalFinding} onChange={onWebhookOnCriticalFindingChange} description="Send webhook on critical findings" />
      <SettingToggle label="Email Notifications" checked={emailNotifications} onChange={onEmailNotificationsChange} description="Send email notifications" />
      <SettingInput label="Email Recipient" value={emailRecipient} onChange={onEmailRecipientChange} type="email" placeholder="admin@example.com" description="Email address for notifications" />
      <div className="setting-input-row">
        <div className="setting-label">
          <span className="setting-title">Slack Webhook</span>
          <span className="setting-desc">Slack incoming webhook URL</span>
        </div>
        <div className="setting-input-with-toggle">
          <input type={showSlackWebhook ? 'text' : 'password'} value={slackWebhook} onChange={e => onSlackWebhookChange(e.target.value)} placeholder="https://hooks.slack.com/..." className="setting-input" />
          <button type="button" className="btn btn-sm btn-secondary" onClick={() => setShowSlackWebhook(!showSlackWebhook)} aria-label={showSlackWebhook ? 'Hide Slack webhook' : 'Show Slack webhook'}>
            {showSlackWebhook ? 'Hide' : 'Show'}
          </button>
        </div>
      </div>
    </SettingsSectionCard>
  );
}
