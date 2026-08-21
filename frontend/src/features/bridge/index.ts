export { CATALOG, getCommand, PROTOCOL_VERSION } from './commands';
export { ConsoleClient } from './client';
export { ConsoleConnection } from './connection';
export { ConsoleStream } from './stream';
export { canCallCommand, shouldCallJwtNotifications, shouldUseConsoleInbox } from './authGate';
export { notificationsFetchUrl, notificationsStreamUrl, shouldFetchPath, transportHints } from './demoChannel';
export { jobTone, notificationTone, progressLabel, unreadCount } from './projector';
export { BridgeError } from './errors';
export type {
  ConsoleCommandName,
  ConsoleSession,
  JobCard,
  NotificationCard,
  ResponseEnvelope,
  TransportHints,
} from './types';
