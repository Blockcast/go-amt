/**
 * Unit tests for the Server Manager (output-servers/server-manager.js).
 *
 * The manager is pure coordination logic, so the suite loads the real class
 * and registers fake servers whose methods are jest mocks.
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { ServerManager } = require('../../output-servers/server-manager.js');

function fakeServer(overrides = {}) {
  return {
    enabled: true,
    start: jest.fn().mockResolvedValue(true),
    stop: jest.fn().mockResolvedValue(true),
    broadcastPacket: jest.fn().mockResolvedValue(0),
    ...overrides
  };
}

describe('ServerManager', () => {
  let manager;

  beforeEach(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    manager = new ServerManager();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('registration', () => {
    test('registers, replaces and rejects invalid servers', () => {
      const first = fakeServer();
      const second = fakeServer();

      expect(manager.registerServer('udp', first)).toBe(true);
      expect(manager.registerServer('udp', second)).toBe(true);
      expect(manager.getServer('udp')).toBe(second);
      expect(manager.registerServer('', fakeServer())).toBe(false);
      expect(manager.registerServer('tcp', null)).toBe(false);
      expect(manager.getServerNames()).toEqual(['udp']);
    });

    test('unregisterServer stops a running server before removing it', async () => {
      const udp = fakeServer();
      manager.registerServer('udp', udp);

      expect(await manager.unregisterServer('udp')).toBe(true);
      expect(udp.stop).toHaveBeenCalled();
      expect(manager.getServerCount()).toBe(0);
      expect(await manager.unregisterServer('udp')).toBe(false);
    });
  });

  describe('lifecycle', () => {
    test('startAll reports each result and stays enabled if any server started', async () => {
      manager.registerServer('udp', fakeServer());
      manager.registerServer('tcp', fakeServer({ start: jest.fn().mockRejectedValue(new Error('Port in use')) }));

      const results = await manager.startAll();

      expect(results).toEqual({
        udp: { success: true },
        tcp: { success: false, error: 'Port in use' }
      });
      expect(manager.enabled).toBe(true);
      expect(manager.stats.errors).toEqual([expect.objectContaining({ server: 'tcp', error: 'Port in use' })]);
    });

    test('startAll leaves the manager disabled when every server fails', async () => {
      manager.registerServer('udp', fakeServer({ start: jest.fn().mockRejectedValue(new Error('no')) }));

      await manager.startAll();

      expect(manager.enabled).toBe(false);
    });

    test('stopAll stops servers in reverse registration order', async () => {
      const order = [];
      for (const name of ['udp', 'tcp', 'websocket']) {
        manager.registerServer(name, fakeServer({ stop: jest.fn(async () => { order.push(name); }) }));
      }

      await manager.stopAll();

      expect(order).toEqual(['websocket', 'tcp', 'udp']);
      expect(manager.enabled).toBe(false);
    });

    test('shutdown stops everything and clears the registry', async () => {
      const udp = fakeServer();
      manager.registerServer('udp', udp);

      expect(await manager.shutdown()).toBe(true);
      expect(udp.stop).toHaveBeenCalled();
      expect(manager.getServerCount()).toBe(0);
    });
  });

  describe('packet distribution', () => {
    test('handleIncomingPacket sums enabled servers and survives one that throws', async () => {
      const udp = fakeServer({ broadcastPacket: jest.fn().mockResolvedValue(2) });
      const tcp = fakeServer({ broadcastPacket: jest.fn().mockRejectedValue(new Error('Send failed')) });
      const ws = fakeServer({ broadcastPacket: jest.fn().mockResolvedValue(3) });
      const off = fakeServer({ enabled: false });
      manager.registerServer('udp', udp);
      manager.registerServer('tcp', tcp);
      manager.registerServer('websocket', ws);
      manager.registerServer('off', off);
      const packet = new Uint8Array([1, 2, 3, 4, 5]);

      const total = await manager.handleIncomingPacket(packet, '10.0.0.1', '232.1.1.1', 1234);

      expect(total).toBe(5);
      expect(udp.broadcastPacket).toHaveBeenCalledWith(packet, '10.0.0.1', '232.1.1.1', 1234);
      expect(off.broadcastPacket).not.toHaveBeenCalled();
      expect(manager.stats.totalPackets).toBe(1);
      expect(manager.stats.totalBytes).toBe(5);
    });

    test('broadcastToAll reports per-server outcomes', async () => {
      manager.registerServer('udp', fakeServer({ broadcastPacket: jest.fn().mockResolvedValue(2) }));
      manager.registerServer('tcp', fakeServer({ broadcastPacket: jest.fn().mockRejectedValue(new Error('Failed')) }));
      manager.registerServer('off', fakeServer({ enabled: false }));

      const results = await manager.broadcastToAll(new Uint8Array([1]), '10.0.0.1', '232.1.1.1', 1234);

      expect(results).toEqual({
        udp: { success: true, clientCount: 2 },
        tcp: { success: false, error: 'Failed' },
        off: { skipped: true, reason: 'disabled' }
      });
    });
  });

  describe('status', () => {
    test('checkHealth uses isHealthy when a server provides it', () => {
      manager.registerServer('udp', fakeServer({ isHealthy: () => false, lastError: 'Socket closed' }));
      manager.registerServer('tcp', fakeServer({ enabled: false }));

      expect(manager.checkHealth()).toEqual({
        udp: { enabled: true, healthy: false, lastError: 'Socket closed' },
        tcp: { enabled: false, healthy: true, lastError: null }
      });
      expect(manager.getEnabledServerCount()).toBe(1);
    });

    test('getStats aggregates subscribers and packets across servers', () => {
      manager.registerServer('udp', fakeServer({ getStats: () => ({ subscriptions: 5, packetsSent: 100 }) }));
      manager.registerServer('tcp', fakeServer({ getStats: () => ({ clients: 3, packetsSent: 50 }) }));

      const stats = manager.getStats();

      expect(stats.totalSubscribers).toBe(8);
      expect(stats.totalServerPackets).toBe(150);
    });

    test('getStatus falls back to enabled when a server has no getStatus', () => {
      manager.registerServer('udp', fakeServer({ getStatus: () => ({ subscriptions: 5 }) }));
      manager.registerServer('tcp', fakeServer());

      const status = manager.getStatus();

      expect(status.manager).toEqual(expect.objectContaining({ serverCount: 2, enabledCount: 2 }));
      expect(status.servers).toEqual({ udp: { subscriptions: 5 }, tcp: { enabled: true } });
    });
  });
});
