import { z } from 'zod';

export const DashboardStatsSchema = z.object({
  total_targets: z.number(),
  total_findings: z.number(),
  active_jobs: z.number(),
  pipeline_health_score: z.number(),
  pipeline_health_label: z.string(),
  avg_progress: z.number(),
  stage_counts: z.record(z.string(), z.number()),
  severity_counts: z.record(z.string(), z.number()),
  completed_jobs: z.number(),
  failed_jobs: z.number(),
  completed_targets: z.number(),
  trend_data: z.array(z.number()).optional(),
  findings_summary: z.record(z.string(), z.any()).optional(),
  mesh_health: z.record(z.string(), z.any()).optional(),
});

export const TargetSchema = z.object({
  id: z.string(),
  url: z.string(),
  name: z.string().optional(),
  tags: z.array(z.string()).default([]),
  last_scan: z.string().optional(),
  status: z.string().default('unknown'),
  risk_score: z.number().default(0),
});

export const JobSchema = z.object({
  id: z.string(),
  target_name: z.string().optional(),
  status: z.string(),
  started_at: z.string().optional(),
  progress_percent: z.number().optional().default(0),
  stage: z.string().optional().default('init'),
  error: z.string().optional(),
}).passthrough();

export const FindingSchema = z.object({
  id: z.string(),
  job_id: z.string(),
  target_id: z.string(),
  type: z.string(),
   
  severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
  title: z.string(),
  description: z.string(),
  remediation: z.string().optional(),
  proof: z.string().optional(),
  timestamp: z.string(),
   
  status: z.enum(['active', 'resolved', 'false_positive', 'ignored']).default('active'),
});

export const FindingsListSchema = z.array(FindingSchema);

export const RegistrySchema = z.object({
  modules: z.array(z.object({
    id: z.string(),
    name: z.string(),
    description: z.string(),
    options: z.record(z.string(), z.any()).default({}),
  })),
  profiles: z.array(z.object({
    id: z.string(),
    name: z.string(),
    description: z.string(),
    modules: z.array(z.string()),
  })),
});

export const AppSettingsSchema = z.object({
  language: z.string().default('en'),
  dashboard: z.object({
    autoRefresh: z.boolean().default(false),
    refreshInterval: z.number().default(30),
    defaultJobFilter: z.string().default('all'),
    widgets: z.object({
      healthCheck: z.boolean().default(true),
      recentJobs: z.boolean().default(true),
      activeTargets: z.boolean().default(true),
      severityBreakdown: z.boolean().default(true),
      quickActions: z.boolean().default(true),
      systemStats: z.boolean().default(false),
    }).default({
      healthCheck: true,
      recentJobs: true,
      activeTargets: true,
      severityBreakdown: true,
      quickActions: true,
      systemStats: false,
    }),
   
    layout: z.enum(['grid', 'list', 'compact']).default('grid'),
  }).default({
    autoRefresh: false,
    refreshInterval: 30,
    defaultJobFilter: 'all',
    widgets: {
      healthCheck: true,
      recentJobs: true,
      activeTargets: true,
      severityBreakdown: true,
      quickActions: true,
      systemStats: false,
    },
    layout: 'grid',
  }),
  notifications: z.object({
    jobComplete: z.boolean().default(true),
    jobFailed: z.boolean().default(true),
    criticalFindings: z.boolean().default(true),
    soundEnabled: z.boolean().default(false),
  }).default({
    jobComplete: true,
    jobFailed: true,
    criticalFindings: true,
    soundEnabled: false,
  }),
  security: z.object({
    confirmDestructiveActions: z.boolean().default(true),
    showSensitiveData: z.boolean().default(false),
    autoLogoutMinutes: z.number().default(0),
  }).default({
    confirmDestructiveActions: true,
    showSensitiveData: false,
    autoLogoutMinutes: 0,
  }),
  pipeline: z.object({
    concurrency: z.number().default(4),
    timeout: z.number().default(300),
    maxRetries: z.number().default(3),
    verboseLogging: z.boolean().default(false),
    parallelModules: z.boolean().default(true),
  }).default({
    concurrency: 4,
    timeout: 300,
    maxRetries: 3,
    verboseLogging: false,
    parallelModules: true,
  }),
  api: z.object({
    baseUrl: z.string().default('http://localhost:8000'),
    timeout: z.number().default(30),
    apiKey: z.string().default(''),
  }).default({
    baseUrl: 'http://localhost:8000',
    timeout: 30,
    apiKey: '',
  }),
  reports: z.object({
   
    format: z.enum(['json', 'html', 'pdf', 'csv']).default('json'),
    includeRawResponses: z.boolean().default(false),
    includeProofOfConcept: z.boolean().default(true),
    autoSave: z.boolean().default(true),
    outputDirectory: z.string().default('./output'),
  }).default({
    format: 'json',
    includeRawResponses: false,
    includeProofOfConcept: true,
    autoSave: true,
    outputDirectory: './output',
  }),
  integrations: z.object({
    webhookUrl: z.string().default(''),
    webhookOnJobComplete: z.boolean().default(true),
    webhookOnCriticalFinding: z.boolean().default(true),
    emailNotifications: z.boolean().default(false),
    emailRecipient: z.string().default(''),
    slackWebhook: z.string().default(''),
  }).default({
    webhookUrl: '',
    webhookOnJobComplete: true,
    webhookOnCriticalFinding: true,
    emailNotifications: false,
    emailRecipient: '',
    slackWebhook: '',
  }),
  scanProfiles: z.object({
   
    defaultProfile: z.enum(['quick', 'standard', 'deep', 'custom']).default('standard'),
    includeNuclei: z.boolean().default(true),
    includePassiveAnalysis: z.boolean().default(true),
    includeActiveProbes: z.boolean().default(true),
    includeIntelligence: z.boolean().default(true),
  }).default({
    defaultProfile: 'standard',
    includeNuclei: true,
    includePassiveAnalysis: true,
    includeActiveProbes: true,
    includeIntelligence: true,
  }),
  experimental: z.object({
    enabled: z.boolean().default(false),
    behaviorAnalysis: z.boolean().default(false),
    attackValidation: z.boolean().default(false),
    graphIntelligence: z.boolean().default(false),
    polymorphicEvasion: z.boolean().default(false),
    antiForensicMode: z.boolean().default(false),
  }).default({
    enabled: false,
    behaviorAnalysis: false,
    attackValidation: false,
    graphIntelligence: false,
    polymorphicEvasion: false,
    antiForensicMode: false,
  }),
  performance: z.object({
    enableCaching: z.boolean().default(true),
    cacheDuration: z.number().default(300),
    lazyLoadModules: z.boolean().default(true),
    maxConcurrentRequests: z.number().default(10),
  }).default({
    enableCaching: true,
    cacheDuration: 300,
    lazyLoadModules: true,
    maxConcurrentRequests: 10,
  }),
  shortcuts: z.object({
    toggleTheme: z.string().default('D'),
    openSettings: z.string().default('S'),
    refreshDashboard: z.string().default('R'),
    quickScan: z.string().default('Q'),
  }).default({
    toggleTheme: 'D',
    openSettings: 'S',
    refreshDashboard: 'R',
    quickScan: 'Q',
  }),
  profiles: z.object({
    savedProfiles: z.array(z.object({
      id: z.string(),
      name: z.string(),
      settings: z.record(z.string(), z.unknown()), // Partial AppSettings
      createdAt: z.string(),
    })).default([]),
    activeProfileId: z.string().nullable().default(null),
  }).default({
    savedProfiles: [],
    activeProfileId: null,
  }),
  logging: z.object({
   
    level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    includeTimestamps: z.boolean().default(true),
    maxLogLines: z.number().default(1000),
    autoScroll: z.boolean().default(true),
  }).default({
    level: 'info',
    includeTimestamps: true,
    maxLogLines: 1000,
    autoScroll: true,
  }),
  rateLimiting: z.object({
    enabled: z.boolean().default(true),
    requestsPerSecond: z.number().default(10),
    burstSize: z.number().default(20),
    backoffMultiplier: z.number().default(2),
  }).default({
    enabled: true,
    requestsPerSecond: 10,
    burstSize: 20,
    backoffMultiplier: 2,
  }),
});
