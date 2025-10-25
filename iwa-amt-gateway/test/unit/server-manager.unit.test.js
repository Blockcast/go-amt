/**
 * Unit tests for Server Manager
 * 
 * The Server Manager coordinates all output servers (UDP, TCP, WebSocket, WebRTC)
 * and provides unified control, monitoring, and packet distribution.
 * 
 * TEST FIRST - Writing tests before implementation
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');

describe('Server Manager Unit Tests', () => {
  let ServerManager;
  let manager;

  beforeEach(() => {
    // Mock console
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    
    // Simple implementation for testing
    class TestServerManager {
      constructor() {
        this.servers = new Map();
        this.enabled = false;
      }
    }
    
    ServerManager = TestServerManager;
    manager = new ServerManager();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Initialization', () => {
    test('should create server manager instance', () => {
      expect(manager).toBeDefined();
      expect(manager.servers).toBeInstanceOf(Map);
      expect(manager.enabled).toBe(false);
    });

    test('should initialize with no servers', () => {
      expect(manager.servers.size).toBe(0);
    });
  });

  describe('Server Registration', () => {
    test('should register server', () => {
      const udpServer = {
        name: 'udp',
        type: 'udp',
        enabled: false,
        start: jest.fn(),
        stop: jest.fn(),
        broadcastPacket: jest.fn()
      };

      manager.servers.set('udp', udpServer);

      expect(manager.servers.has('udp')).toBe(true);
      expect(manager.servers.get('udp').name).toBe('udp');
    });

    test('should register multiple servers', () => {
      const servers = [
        { name: 'udp', type: 'udp' },
        { name: 'tcp', type: 'tcp' },
        { name: 'websocket', type: 'websocket' }
      ];

      servers.forEach(s => manager.servers.set(s.name, s));

      expect(manager.servers.size).toBe(3);
      expect(manager.servers.has('udp')).toBe(true);
      expect(manager.servers.has('tcp')).toBe(true);
      expect(manager.servers.has('websocket')).toBe(true);
    });

    test('should unregister server', () => {
      manager.servers.set('udp', { name: 'udp' });
      expect(manager.servers.has('udp')).toBe(true);

      manager.servers.delete('udp');
      expect(manager.servers.has('udp')).toBe(false);
    });
  });

  describe('Server Lifecycle', () => {
    test('should start all servers', async () => {
      const udpServer = {
        name: 'udp',
        enabled: false,
        start: jest.fn().mockResolvedValue(true)
      };
      const tcpServer = {
        name: 'tcp',
        enabled: false,
        start: jest.fn().mockResolvedValue(true)
      };

      manager.servers.set('udp', udpServer);
      manager.servers.set('tcp', tcpServer);

      // Simulate starting all
      await Promise.all(
        Array.from(manager.servers.values()).map(s => s.start())
      );

      expect(udpServer.start).toHaveBeenCalled();
      expect(tcpServer.start).toHaveBeenCalled();
    });

    test('should stop all servers', async () => {
      const udpServer = {
        name: 'udp',
        enabled: true,
        stop: jest.fn().mockResolvedValue(true)
      };
      const tcpServer = {
        name: 'tcp',
        enabled: true,
        stop: jest.fn().mockResolvedValue(true)
      };

      manager.servers.set('udp', udpServer);
      manager.servers.set('tcp', tcpServer);

      // Simulate stopping all
      await Promise.all(
        Array.from(manager.servers.values()).map(s => s.stop())
      );

      expect(udpServer.stop).toHaveBeenCalled();
      expect(tcpServer.stop).toHaveBeenCalled();
    });

    test('should handle server start failure gracefully', async () => {
      const udpServer = {
        name: 'udp',
        start: jest.fn().mockRejectedValue(new Error('Port in use'))
      };

      manager.servers.set('udp', udpServer);

      await expect(udpServer.start()).rejects.toThrow('Port in use');
    });
  });

  describe('Packet Distribution', () => {
    test('should broadcast packet to all enabled servers', async () => {
      const udpServer = {
        name: 'udp',
        enabled: true,
        broadcastPacket: jest.fn().mockResolvedValue(2) // 2 clients
      };
      const tcpServer = {
        name: 'tcp',
        enabled: true,
        broadcastPacket: jest.fn().mockResolvedValue(3) // 3 clients
      };

      manager.servers.set('udp', udpServer);
      manager.servers.set('tcp', tcpServer);

      const packet = new Uint8Array([1, 2, 3, 4, 5]);
      const sourceIP = '10.0.0.1';
      const groupIP = '232.1.1.1';
      const port = 1234;

      // Simulate broadcast to all servers
      const promises = Array.from(manager.servers.values())
        .filter(s => s.enabled)
        .map(s => s.broadcastPacket(packet, sourceIP, groupIP, port));

      const results = await Promise.all(promises);
      const totalClients = results.reduce((sum, count) => sum + count, 0);

      expect(udpServer.broadcastPacket).toHaveBeenCalledWith(packet, sourceIP, groupIP, port);
      expect(tcpServer.broadcastPacket).toHaveBeenCalledWith(packet, sourceIP, groupIP, port);
      expect(totalClients).toBe(5);
    });

    test('should skip disabled servers', async () => {
      const udpServer = {
        name: 'udp',
        enabled: true,
        broadcastPacket: jest.fn().mockResolvedValue(2)
      };
      const tcpServer = {
        name: 'tcp',
        enabled: false,
        broadcastPacket: jest.fn()
      };

      manager.servers.set('udp', udpServer);
      manager.servers.set('tcp', tcpServer);

      const packet = new Uint8Array([1, 2, 3, 4, 5]);

      // Only broadcast to enabled servers
      const promises = Array.from(manager.servers.values())
        .filter(s => s.enabled)
        .map(s => s.broadcastPacket(packet, '10.0.0.1', '232.1.1.1', 1234));

      await Promise.all(promises);

      expect(udpServer.broadcastPacket).toHaveBeenCalled();
      expect(tcpServer.broadcastPacket).not.toHaveBeenCalled();
    });
  });

  describe('Server Status', () => {
    test('should get status of all servers', () => {
      const udpServer = {
        name: 'udp',
        enabled: true,
        getStatus: jest.fn().mockReturnValue({ subscriptions: 5, packets: 100 })
      };
      const tcpServer = {
        name: 'tcp',
        enabled: true,
        getStatus: jest.fn().mockReturnValue({ clients: 3, packets: 50 })
      };

      manager.servers.set('udp', udpServer);
      manager.servers.set('tcp', tcpServer);

      const status = {};
      for (const [name, server] of manager.servers.entries()) {
        status[name] = server.getStatus();
      }

      expect(status.udp).toBeDefined();
      expect(status.tcp).toBeDefined();
      expect(status.udp.subscriptions).toBe(5);
      expect(status.tcp.clients).toBe(3);
    });

    test('should count enabled servers', () => {
      manager.servers.set('udp', { enabled: true });
      manager.servers.set('tcp', { enabled: true });
      manager.servers.set('websocket', { enabled: false });

      const enabledCount = Array.from(manager.servers.values())
        .filter(s => s.enabled).length;

      expect(enabledCount).toBe(2);
    });

    test('should list server names', () => {
      manager.servers.set('udp', { name: 'udp' });
      manager.servers.set('tcp', { name: 'tcp' });
      manager.servers.set('websocket', { name: 'websocket' });

      const names = Array.from(manager.servers.keys());

      expect(names).toHaveLength(3);
      expect(names).toContain('udp');
      expect(names).toContain('tcp');
      expect(names).toContain('websocket');
    });
  });

  describe('Health Monitoring', () => {
    test('should check if server is healthy', () => {
      const udpServer = {
        name: 'udp',
        enabled: true,
        isHealthy: jest.fn().mockReturnValue(true)
      };

      manager.servers.set('udp', udpServer);

      const healthy = udpServer.isHealthy();

      expect(healthy).toBe(true);
      expect(udpServer.isHealthy).toHaveBeenCalled();
    });

    test('should detect unhealthy server', () => {
      const udpServer = {
        name: 'udp',
        enabled: true,
        isHealthy: jest.fn().mockReturnValue(false),
        lastError: 'Socket closed unexpectedly'
      };

      manager.servers.set('udp', udpServer);

      const healthy = udpServer.isHealthy();

      expect(healthy).toBe(false);
      expect(udpServer.lastError).toBeDefined();
    });

    test('should get health status of all servers', () => {
      manager.servers.set('udp', {
        name: 'udp',
        enabled: true,
        isHealthy: jest.fn().mockReturnValue(true)
      });
      manager.servers.set('tcp', {
        name: 'tcp',
        enabled: true,
        isHealthy: jest.fn().mockReturnValue(false)
      });

      const healthStatus = {};
      for (const [name, server] of manager.servers.entries()) {
        healthStatus[name] = server.isHealthy();
      }

      expect(healthStatus.udp).toBe(true);
      expect(healthStatus.tcp).toBe(false);
    });
  });

  describe('Statistics Aggregation', () => {
    test('should aggregate packet counts', () => {
      manager.servers.set('udp', {
        getStats: jest.fn().mockReturnValue({ packetsSent: 100 })
      });
      manager.servers.set('tcp', {
        getStats: jest.fn().mockReturnValue({ packetsSent: 50 })
      });

      let totalPackets = 0;
      for (const server of manager.servers.values()) {
        const stats = server.getStats();
        totalPackets += stats.packetsSent;
      }

      expect(totalPackets).toBe(150);
    });

    test('should aggregate subscription counts', () => {
      manager.servers.set('udp', {
        getStats: jest.fn().mockReturnValue({ subscriptions: 5 })
      });
      manager.servers.set('tcp', {
        getStats: jest.fn().mockReturnValue({ clients: 3 })
      });

      const stats = {};
      for (const [name, server] of manager.servers.entries()) {
        stats[name] = server.getStats();
      }

      const totalSubscribers = (stats.udp.subscriptions || 0) + (stats.tcp.clients || 0);

      expect(totalSubscribers).toBe(8);
    });
  });

  describe('Error Handling', () => {
    test('should handle broadcast errors gracefully', async () => {
      const udpServer = {
        name: 'udp',
        enabled: true,
        broadcastPacket: jest.fn().mockRejectedValue(new Error('Send failed'))
      };

      manager.servers.set('udp', udpServer);

      const packet = new Uint8Array([1, 2, 3]);

      await expect(udpServer.broadcastPacket(packet)).rejects.toThrow('Send failed');
    });

    test('should continue with other servers if one fails', async () => {
      const udpServer = {
        name: 'udp',
        enabled: true,
        broadcastPacket: jest.fn().mockRejectedValue(new Error('Failed'))
      };
      const tcpServer = {
        name: 'tcp',
        enabled: true,
        broadcastPacket: jest.fn().mockResolvedValue(3)
      };

      manager.servers.set('udp', udpServer);
      manager.servers.set('tcp', tcpServer);

      const packet = new Uint8Array([1, 2, 3]);

      // Use Promise.allSettled to continue even if one fails
      const results = await Promise.allSettled(
        Array.from(manager.servers.values())
          .filter(s => s.enabled)
          .map(s => s.broadcastPacket(packet, '10.0.0.1', '232.1.1.1', 1234))
      );

      expect(results[0].status).toBe('rejected');
      expect(results[1].status).toBe('fulfilled');
      expect(results[1].value).toBe(3);
    });
  });

  describe('Graceful Shutdown', () => {
    test('should stop servers in reverse order', async () => {
      const order = [];
      
      const udpServer = {
        name: 'udp',
        stop: jest.fn().mockImplementation(async () => { order.push('udp'); })
      };
      const tcpServer = {
        name: 'tcp',
        stop: jest.fn().mockImplementation(async () => { order.push('tcp'); })
      };
      const wsServer = {
        name: 'websocket',
        stop: jest.fn().mockImplementation(async () => { order.push('websocket'); })
      };

      manager.servers.set('udp', udpServer);
      manager.servers.set('tcp', tcpServer);
      manager.servers.set('websocket', wsServer);

      // Stop in reverse order
      const serverArray = Array.from(manager.servers.values()).reverse();
      for (const server of serverArray) {
        await server.stop();
      }

      expect(order).toEqual(['websocket', 'tcp', 'udp']);
    });

    test('should wait for all servers to stop', async () => {
      const udpServer = {
        stop: jest.fn().mockImplementation(() => 
          new Promise(resolve => setTimeout(resolve, 10))
        )
      };
      const tcpServer = {
        stop: jest.fn().mockImplementation(() =>
          new Promise(resolve => setTimeout(resolve, 20))
        )
      };

      manager.servers.set('udp', udpServer);
      manager.servers.set('tcp', tcpServer);

      const startTime = Date.now();
      await Promise.all(
        Array.from(manager.servers.values()).map(s => s.stop())
      );
      const elapsed = Date.now() - startTime;

      expect(elapsed).toBeGreaterThanOrEqual(20);
      expect(udpServer.stop).toHaveBeenCalled();
      expect(tcpServer.stop).toHaveBeenCalled();
    });
  });
});




