import { describe, expect, it } from 'vitest';
import { shouldFetchNotifications } from '@/features/notifications/policy';
import { sessionHasBearerToken } from '@/features/auth/session';

describe('notification fetch policy', () => {
  it('skips the inbox without a bearer token', () => {
    expect(shouldFetchNotifications(null)).toBe(false);
    expect(shouldFetchNotifications('')).toBe(false);
  });

  it('fetches when a JWT is present', () => {
    expect(shouldFetchNotifications('jwt-token')).toBe(true);
  });
});

describe('console session kinds', () => {
  it('demo and guest never present a bearer token', () => {
    expect(sessionHasBearerToken('demo', 'leftover')).toBe(false);
    expect(sessionHasBearerToken('guest', 'leftover')).toBe(false);
    expect(sessionHasBearerToken('jwt', 'abc')).toBe(true);
  });
});
