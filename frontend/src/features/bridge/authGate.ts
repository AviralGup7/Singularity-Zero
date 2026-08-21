import { getCommand } from './commands';
import type { ConsoleAuthMode, ConsoleCommandName, ConsoleSession } from './types';

export interface GateInput {
  session?: ConsoleSession | null;
  bearerToken?: string | null;
}

export function hasCapability(session: ConsoleSession | null | undefined, capability: string | null): boolean {
  if (!capability) return true;
  if (!session) return false;
  return session.capabilities.includes(capability);
}

export function isDemoOrGuest(session: ConsoleSession | null | undefined): boolean {
  if (!session) return false;
  return session.kind === 'demo' || session.kind === 'guest';
}

export function jwtNotificationsAllowed(input: GateInput): boolean {
  if (input.bearerToken && input.bearerToken.trim()) return true;
  return Boolean(input.session?.has_bearer_token);
}

export function canCallCommand(name: ConsoleCommandName, input: GateInput): { ok: boolean; reason: string } {
  const spec = getCommand(name);
  return canCallSpec(spec.auth, spec.capability, input);
}

export function canCallSpec(
  auth: ConsoleAuthMode,
  capability: string | null,
  input: GateInput,
): { ok: boolean; reason: string } {
  if (auth === 'public') {
    return { ok: true, reason: 'public' };
  }
  const session = input.session ?? null;
  if (!session) {
    return { ok: false, reason: 'sign_in_required' };
  }
  if (auth === 'bearer' && !jwtNotificationsAllowed(input)) {
    return { ok: false, reason: 'bearer_required' };
  }
  if (!hasCapability(session, capability)) {
    return { ok: false, reason: `missing:${capability}` };
  }
  return { ok: true, reason: auth };
}

/**
 * JWT inbox HTTP must not run after Demo Sign In. Use the console channel.
 */
export function shouldCallJwtNotifications(input: GateInput): boolean {
  return jwtNotificationsAllowed(input);
}

export function shouldUseConsoleInbox(input: GateInput): boolean {
  if (jwtNotificationsAllowed(input)) return false;
  return isDemoOrGuest(input.session);
}
