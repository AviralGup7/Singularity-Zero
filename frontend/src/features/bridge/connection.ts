import { ConsoleClient } from './client';
import type { ConsoleSession, TransportHints } from './types';

export type ConnectionState = 'idle' | 'connecting' | 'ready' | 'degraded' | 'closed';

export interface HandshakeResult {
  connectionId: string;
  session: ConsoleSession;
  catalog: Array<{ name: string; path: string }>;
  transport: TransportHints;
}

export class ConsoleConnection {
  state: ConnectionState = 'idle';
  connectionId: string | null = null;
  session: ConsoleSession | null = null;
  transport: TransportHints | null = null;
  lastError: string | null = null;

  constructor(private readonly client: ConsoleClient) {}

  async open(name = 'Demo Analyst', role = 'analyst'): Promise<HandshakeResult> {
    this.state = 'connecting';
    const response = await this.client.call('handshake.open', {
      client: 'security-console',
      protocol: '1.0',
      kind: 'demo',
      name,
      role,
    });
    if (!response.ok) {
      this.state = 'degraded';
      this.lastError = response.error?.message ?? 'handshake failed';
      throw new Error(this.lastError);
    }
    const data = response.data as {
      connection_id: string;
      session: ConsoleSession;
      catalog: Array<{ name: string; path: string }>;
      transport: TransportHints;
      notifications_policy?: TransportHints;
    };
    this.connectionId = data.connection_id;
    this.session = data.session;
    this.transport = data.notifications_policy ?? data.transport;
    this.state = 'ready';
    this.lastError = null;
    return {
      connectionId: data.connection_id,
      session: data.session,
      catalog: data.catalog,
      transport: this.transport,
    };
  }

  async ping(): Promise<boolean> {
    const response = await this.client.call('handshake.ping', {}, { connection_id: this.connectionId ?? undefined });
    if (!response.ok) {
      this.state = 'degraded';
      return false;
    }
    this.state = 'ready';
    return true;
  }

  async close(): Promise<void> {
    if (this.connectionId) {
      await this.client.call('handshake.close', {}, { connection_id: this.connectionId });
    }
    this.state = 'closed';
    this.connectionId = null;
  }
}
