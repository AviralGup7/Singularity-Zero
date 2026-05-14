import { useState } from 'react';
import { SettingsSectionCard, SettingToggle, SettingInput } from '../SettingsComponents';

interface _WebhookConfig {
  enabled: boolean;
  url: string;
  events: string[];
  secret: string;
}

interface _SlackConfig {
  enabled: boolean;
  webhookUrl: string;
  channel: string;
  username: string;
  iconEmoji: string;
}

interface NotificationsSectionProps {
  jobCompleteNotification: boolean;
  jobFailedNotification: boolean;
  criticalFindingsNotification: boolean;
  soundEnabled: boolean;
  onJobCompleteNotificationChange: (v: boolean) => void;
  onJobFailedNotificationChange: (v: boolean) => void;
  onCriticalFindingsNotificationChange: (v: boolean) => void;
  onSoundEnabledChange: (v: boolean) => void;
}

export function NotificationsSection({
  jobCompleteNotification,
  jobFailedNotification,
  criticalFindingsNotification,
  soundEnabled,
  onJobCompleteNotificationChange,
  onJobFailedNotificationChange,
  onCriticalFindingsNotificationChange,
  onSoundEnabledChange,
}: NotificationsSectionProps) {
  const [webhookEnabled, setWebhookEnabled] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookSecret, setWebhookSecret] = useState('');
  const [slackEnabled, setSlackEnabled] = useState(false);
  const [slackWebhookUrl, setSlackWebhookUrl] = useState('');
  const [slackChannel, setSlackChannel] = useState('#security-alerts');
  const [testStatus, setTestStatus] = useState<'idle' | 'loading' | 'success' | 'error'>('idle');

  const handleTestWebhook = async () => {
    setTestStatus('loading');
    try {
      await fetch('/api/webhooks/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: webhookUrl, secret: webhookSecret }),
      });
      setTestStatus('success');
      setTimeout(() => setTestStatus('idle'), 3000);
    } catch {
      setTestStatus('error');
      setTimeout(() => setTestStatus('idle'), 3000);
    }
  };

  const handleTestSlack = async () => {
    setTestStatus('loading');
    try {
      await fetch('/api/webhooks/test-slack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: slackWebhookUrl, channel: slackChannel }),
      });
      setTestStatus('success');
      setTimeout(() => setTestStatus('idle'), 3000);
    } catch {
      setTestStatus('error');
      setTimeout(() => setTestStatus('idle'), 3000);
    }
  };

  return (
    <div>
      <SettingsSectionCard title="Notifications" icon="🔔">
        <SettingToggle label="Job Complete" checked={jobCompleteNotification} onChange={onJobCompleteNotificationChange} description="Notify when a job finishes" />
        <SettingToggle label="Job Failed" checked={jobFailedNotification} onChange={onJobFailedNotificationChange} description="Notify when a job fails" />
        <SettingToggle label="Critical Findings" checked={criticalFindingsNotification} onChange={onCriticalFindingsNotificationChange} description="Notify on critical severity findings" />
        <SettingToggle label="Sound" checked={soundEnabled} onChange={onSoundEnabledChange} description="Play notification sounds" />
      </SettingsSectionCard>

      <SettingsSectionCard title="Webhook Notifications" icon="🔗">
        <p className="text-sm text-muted mb-4">
          Send scan results and alerts to any HTTP webhook endpoint. Supports signature verification with HMAC-SHA256.
        </p>

        <SettingToggle label="Enable Webhook" checked={webhookEnabled} onChange={setWebhookEnabled} description="POST scan results to external webhook URL" />

        {webhookEnabled && (
          <div className="webhook-config-form mt-4 space-y-4">
            <SettingInput
              label="Webhook URL"
              type="url"
              value={webhookUrl}
              onChange={setWebhookUrl}
              placeholder="https://example.com/webhook/cyber-pipeline"
              description="The URL that will receive POST requests with scan data"
            />

            <SettingInput
              label="Signing Secret"
              type="password"
              value={webhookSecret}
              onChange={setWebhookSecret}
              placeholder="whsec_your_webhook_secret"
              description="Optional secret for HMAC signature verification"
            />

            <div className="flex gap-2 mt-2">
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleTestWebhook}
                disabled={testStatus === 'loading' || !webhookUrl}
              >
                {testStatus === 'loading' ? 'Testing...' : 'Test Webhook'}
              </button>
              {testStatus === 'success' && (
                <span className="text-success text-sm self-center">✓ Webhook test sent successfully</span>
              )}
              {testStatus === 'error' && (
                <span className="text-danger text-sm self-center">✗ Webhook test failed</span>
              )}
            </div>

            <div className="webhook-events mt-4">
              <h4 className="text-sm font-semibold mb-2">Events to send:</h4>
              <div className="flex flex-wrap gap-2">
                {['scan_started', 'scan_completed', 'scan_failed', 'critical_finding', 'job_stalled'].map((event) => (
                  <label key={event} className="webhook-event-checkbox">
                    <input type="checkbox" defaultChecked />
                    <code className="text-xs">{event}</code>
                  </label>
                ))}
              </div>
            </div>
          </div>
        )}
      </SettingsSectionCard>

      <SettingsSectionCard title="Slack Notifications" icon="💬">
        <p className="text-sm text-muted mb-4">
          Send scan notifications to a Slack channel via Incoming Webhook.
        </p>

        <SettingToggle label="Enable Slack" checked={slackEnabled} onChange={setSlackEnabled} description="Send notifications to Slack channel" />

        {slackEnabled && (
          <div className="slack-config-form mt-4 space-y-4">
            <SettingInput
              label="Slack Webhook URL"
              type="url"
              value={slackWebhookUrl}
              onChange={setSlackWebhookUrl}
              placeholder="https://hooks.slack.com/services/T00/B00/xxx"
              description="Slack Incoming Webhook URL from your Slack app settings"
            />

            <div className="grid grid-cols-2 gap-4">
              <SettingInput
                label="Channel"
                type="text"
                value={slackChannel}
                onChange={setSlackChannel}
                placeholder="#security-alerts"
                description="Slack channel to post to"
              />

              <SettingInput
                label="Username"
                type="text"
                value="CyberPipeline"
                onChange={() => {}}
                placeholder="CyberPipeline"
                description="Display name for messages"
              />
            </div>

            <div className="flex gap-2 mt-2">
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleTestSlack}
                disabled={testStatus === 'loading' || !slackWebhookUrl}
              >
                {testStatus === 'loading' ? 'Testing...' : 'Test Slack'}
              </button>
              {testStatus === 'success' && (
                <span className="text-success text-sm self-center">✓ Slack test message sent</span>
              )}
              {testStatus === 'error' && (
                <span className="text-danger text-sm self-center">✗ Slack test failed</span>
              )}
            </div>

            <div className="slack-previews mt-4">
              <h4 className="text-sm font-semibold mb-2">Notification previews:</h4>
              <div className="space-y-2">
                <div className="slack-preview-card">
                  <strong>🟢 Scan Complete:</strong>
                  <p className="text-xs text-muted mt-1">
                    Scan of <code>example.com</code> completed in 15m — 2 Critical, 5 High findings
                  </p>
                </div>
                <div className="slack-preview-card">
                  <strong>🔴 Scan Failed:</strong>
                  <p className="text-xs text-muted mt-1">
                    Scan of <code>example.com</code> failed: Connection timeout after 300s
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}
      </SettingsSectionCard>
    </div>
  );
}
