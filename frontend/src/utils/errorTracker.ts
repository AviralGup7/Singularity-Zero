export interface ErrorContext {
  component?: string;
  action?: string;
  state?: Record<string, unknown>;
  url?: string;
  timestamp: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

export interface TrackedError {
  id: string;
  error: Error;
  context: ErrorContext;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

const ERROR_STORAGE_KEY = 'cyber-pipeline-errors';
const MAX_ERRORS = 500;

let errorTrackerInstance: ErrorTracker | null = null;

export class ErrorTracker {
  private errors: TrackedError[] = [];
  private sentryDsn: string | null = null;

  constructor(sentryDsn?: string) {
    this.sentryDsn = sentryDsn || null;
    this.loadErrors();
  }

  static getInstance(sentryDsn?: string): ErrorTracker {
    if (!errorTrackerInstance) {
      errorTrackerInstance = new ErrorTracker(sentryDsn);
    }
    return errorTrackerInstance;
  }

  static resetInstance(): void {
    errorTrackerInstance = null;
  }

  captureError(error: Error | string, context: Partial<ErrorContext> = {}): TrackedError {
    const errorObj = typeof error === 'string' ? new Error(error) : error;

    const trackedError: TrackedError = {
      id: `error-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      error: errorObj,
      context: {
        component: context.component,
        action: context.action,
        state: context.state,
        url: context.url || window.location.href,
        timestamp: new Date().toISOString(),
        userAgent: '[REDACTED]',
        metadata: context.metadata,
      },
      severity: this.determineSeverity(errorObj, context),
    };

    this.errors.unshift(trackedError);
    if (this.errors.length > MAX_ERRORS) {
      this.errors = this.errors.slice(0, MAX_ERRORS);
    }

    this.persistErrors();
    this.logToConsole(trackedError);
    this.sendToSentry(trackedError);

    return trackedError;
  }

  captureException(error: Error, context?: Partial<ErrorContext>): TrackedError {
    return this.captureError(error, context);
  }

  captureMessage(message: string, context?: Partial<ErrorContext>): TrackedError {
    return this.captureError(message, context);
  }

  getErrors(): TrackedError[] {
    return [...this.errors];
  }

  getErrorsByComponent(component: string): TrackedError[] {
    return this.errors.filter((e) => e.context.component === component);
  }

  getErrorsBySeverity(severity: TrackedError['severity']): TrackedError[] {
    return this.errors.filter((e) => e.severity === severity);
  }

  clearErrors(): void {
    this.errors = [];
    sessionStorage.removeItem(ERROR_STORAGE_KEY);
  }

  exportErrors(): string {
    return JSON.stringify(
      {
        exportedAt: new Date().toISOString(),
        totalErrors: this.errors.length,
        errors: this.errors.map((e) => ({
          id: e.id,
          message: e.error.message,
          stack: e.error.stack,
          context: e.context,
          severity: e.severity,
        })),
      },
      null,
      2
    );
  }

  private determineSeverity(
    error: Error,
    context: Partial<ErrorContext>
  ): TrackedError['severity'] {
    if (context.metadata?.severity) return context.metadata.severity as TrackedError['severity'];
    if (error.name === 'TypeError' || error.name === 'ReferenceError') return 'high';
    if (error.name === 'NetworkError' || error.name === 'AbortError') return 'medium';
    return 'low';
  }

  private logToConsole(trackedError: TrackedError): void {
    const { component, action, url, timestamp } = trackedError.context;
    console.group(`[ErrorTracker] ${trackedError.severity.toUpperCase()}`);
    console.error('Error:', trackedError.error.message);
    if (trackedError.error.stack) console.error('Stack:', trackedError.error.stack);
    console.log('Component:', component || 'N/A');
    console.log('Action:', action || 'N/A');
    console.log('URL:', url);
    console.log('Timestamp:', timestamp);
    if (trackedError.context.state) console.log('State:', trackedError.context.state);
    console.groupEnd();
  }

  private sendToSentry(trackedError: TrackedError): void {
    if (!this.sentryDsn) return;
    // Placeholder for actual Sentry client integration
    if (import.meta.env.DEV) {
      console.log('[Sentry Stub] Sending error:', trackedError.id);
    }
  }

  private loadErrors(): void {
    try {
      const raw = sessionStorage.getItem(ERROR_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        this.errors = parsed.map((e: Record<string, unknown>) => {
          const err = new Error(e.message as string);
          err.name = (e.name as string) || 'Error';
          err.stack = e.stack as string;
          return {
            ...e,
            error: err,
          };
        });
      }
    } catch {
      this.errors = [];
    }
  }

  private persistErrors(): void {
    try {
      const serialized = this.errors.map((e) => {
        const isProd = import.meta.env.PROD;
        return {
          id: e.id,
          name: e.error.name,
          message: e.error.message,
          // SECURITY: Don't persist full stack traces to sessionStorage in production
          stack: isProd ? undefined : e.error.stack,
          context: e.context,
          severity: e.severity,
        };
      });
      sessionStorage.setItem(ERROR_STORAGE_KEY, JSON.stringify(serialized));
    } catch {
      console.warn('Failed to persist errors');
    }
  }
}

export function captureError(error: Error | string, context?: Partial<ErrorContext>): TrackedError {
  return ErrorTracker.getInstance().captureError(error, context);
}

export function captureException(error: Error, context?: Partial<ErrorContext>): TrackedError {
  return ErrorTracker.getInstance().captureException(error, context);
}

export function captureMessage(message: string, context?: Partial<ErrorContext>): TrackedError {
  return ErrorTracker.getInstance().captureMessage(message, context);
}
