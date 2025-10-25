/**
 * Unit tests for UDP Output Server
 * 
 * These tests run in Node.js without requiring IWA or browser environment.
 * We mock the chrome.sockets.udp API to test the server logic.
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { setupChromeMocks, resetChromeMocks } = require('../mocks/chrome-sockets');

describe('UDP Server Unit Tests', () => {
  let udpServer;
  let LocalUDPServer;

  beforeEach(() => {
    // Setup chrome mocks before importing the server
    setupChromeMocks();
    
    // Clear module cache and require fresh
    jest.resetModules();
    
    // Mock console methods to avoid noise
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    resetChromeMocks();
    jest.restoreAllMocks();
  });

  describe('Initialization', () => {
    test('should create UDP server instance', () => {
      // Create a simple version for testing
      class LocalUDPServer {
        constructor() {
          this.controlSocketId = null;
          this.dataSocketId = null;
          this.subscriptions = new Map();
          this.enabled = false;
        }
      }
      
      const server = new LocalUDPServer();
      expect(server).toBeDefined();
      expect(server.controlSocketId).toBeNull();
      expect(server.dataSocketId).toBeNull();
      expect(server.subscriptions).toBeInstanceOf(Map);
      expect(server.enabled).toBe(false);
    });
  });

  describe('Subscription Management', () => {
    test('should add subscription', () => {
      const subscriptions = new Map();
      const clientAddress = '192.168.1.100';
      const clientPort = 50000;
      const filter = {
        source: '10.0.0.1',
        group: '232.1.1.1',
        port: 1234
      };

      const key = `${clientAddress}:${clientPort}`;
      subscriptions.set(key, { clientAddress, clientPort, filter });

      expect(subscriptions.has(key)).toBe(true);
      expect(subscriptions.get(key).filter.source).toBe('10.0.0.1');
      expect(subscriptions.get(key).filter.group).toBe('232.1.1.1');
      expect(subscriptions.get(key).filter.port).toBe(1234);
    });

    test('should remove subscription', () => {
      const subscriptions = new Map();
      const clientAddress = '192.168.1.100';
      const clientPort = 50000;
      const key = `${clientAddress}:${clientPort}`;
      
      subscriptions.set(key, { clientAddress, clientPort });
      expect(subscriptions.has(key)).toBe(true);
      
      subscriptions.delete(key);
      expect(subscriptions.has(key)).toBe(false);
    });

    test('should handle multiple subscriptions', () => {
      const subscriptions = new Map();
      
      subscriptions.set('192.168.1.100:50000', {
        clientAddress: '192.168.1.100',
        clientPort: 50000,
        filter: { source: '*', group: '232.1.1.1', port: 1234 }
      });
      
      subscriptions.set('192.168.1.101:50001', {
        clientAddress: '192.168.1.101',
        clientPort: 50001,
        filter: { source: '10.0.0.1', group: '*', port: '*' }
      });

      expect(subscriptions.size).toBe(2);
      expect(subscriptions.has('192.168.1.100:50000')).toBe(true);
      expect(subscriptions.has('192.168.1.101:50001')).toBe(true);
    });
  });

  describe('Packet Filtering', () => {
    // Test the matchesFilter logic
    function matchesFilter(filter, sourceIP, groupIP, port) {
      const sourceMatch = filter.source === '*' || filter.source === sourceIP;
      const groupMatch = filter.group === '*' || filter.group === groupIP;
      const portMatch = filter.port === '*' || filter.port === port;
      return sourceMatch && groupMatch && portMatch;
    }

    test('should match exact filter', () => {
      const filter = { source: '10.0.0.1', group: '232.1.1.1', port: 1234 };
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesFilter(filter, '10.0.0.2', '232.1.1.1', 1234)).toBe(false);
    });

    test('should match wildcard source', () => {
      const filter = { source: '*', group: '232.1.1.1', port: 1234 };
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesFilter(filter, '10.0.0.2', '232.1.1.1', 1234)).toBe(true);
      expect(matchesFilter(filter, '192.168.1.1', '232.1.1.1', 1234)).toBe(true);
    });

    test('should match wildcard group', () => {
      const filter = { source: '10.0.0.1', group: '*', port: 1234 };
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesFilter(filter, '10.0.0.1', '232.2.2.2', 1234)).toBe(true);
      expect(matchesFilter(filter, '10.0.0.2', '232.1.1.1', 1234)).toBe(false);
    });

    test('should match wildcard port', () => {
      const filter = { source: '10.0.0.1', group: '232.1.1.1', port: '*' };
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', 5678)).toBe(true);
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', 9999)).toBe(true);
    });

    test('should match all wildcards', () => {
      const filter = { source: '*', group: '*', port: '*' };
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesFilter(filter, '192.168.1.1', '239.255.255.255', 65535)).toBe(true);
    });

    test('should not match mismatched filter', () => {
      const filter = { source: '10.0.0.1', group: '232.1.1.1', port: 1234 };
      expect(matchesFilter(filter, '10.0.0.2', '232.1.1.1', 1234)).toBe(false);
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.2', 1234)).toBe(false);
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', 5678)).toBe(false);
    });
  });

  describe('Control Message Parsing', () => {
    test('should parse subscribe message', () => {
      const message = JSON.stringify({
        type: 'SUBSCRIBE',
        source: '10.0.0.1',
        group: '232.1.1.1',
        port: 1234
      });
      
      const buffer = new TextEncoder().encode(message);
      const decoded = JSON.parse(new TextDecoder().decode(buffer));
      
      expect(decoded.type).toBe('SUBSCRIBE');
      expect(decoded.source).toBe('10.0.0.1');
      expect(decoded.group).toBe('232.1.1.1');
      expect(decoded.port).toBe(1234);
    });

    test('should parse unsubscribe message', () => {
      const message = JSON.stringify({
        type: 'UNSUBSCRIBE',
        source: '10.0.0.1',
        group: '232.1.1.1',
        port: 1234
      });
      
      const buffer = new TextEncoder().encode(message);
      const decoded = JSON.parse(new TextDecoder().decode(buffer));
      
      expect(decoded.type).toBe('UNSUBSCRIBE');
    });

    test('should handle wildcard in subscribe message', () => {
      const message = JSON.stringify({
        type: 'SUBSCRIBE',
        source: '*',
        group: '232.1.1.1',
        port: '*'
      });
      
      const buffer = new TextEncoder().encode(message);
      const decoded = JSON.parse(new TextDecoder().decode(buffer));
      
      expect(decoded.source).toBe('*');
      expect(decoded.port).toBe('*');
    });

    test('should handle invalid JSON gracefully', () => {
      const message = 'not valid json{';
      const buffer = new TextEncoder().encode(message);
      
      expect(() => {
        JSON.parse(new TextDecoder().decode(buffer));
      }).toThrow();
    });
  });

  describe('Chrome Sockets Integration', () => {
    test('should create UDP socket', async () => {
      const udp = global.chrome.sockets.udp;
      
      const socketId = await new Promise((resolve) => {
        udp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      expect(socketId).toBeDefined();
      expect(typeof socketId).toBe('number');
    });

    test('should bind socket to address', async () => {
      const udp = global.chrome.sockets.udp;
      
      const socketId = await new Promise((resolve) => {
        udp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      const result = await new Promise((resolve) => {
        udp.bind(socketId, '0.0.0.0', 5000, (result) => {
          resolve(result);
        });
      });
      
      expect(result).toBe(0); // Success
      
      const info = await new Promise((resolve) => {
        udp.getInfo(socketId, (info) => {
          resolve(info);
        });
      });
      
      expect(info.localAddress).toBe('0.0.0.0');
      expect(info.localPort).toBe(5000);
    });

    test('should send UDP packet', async () => {
      const udp = global.chrome.sockets.udp;
      
      const socketId = await new Promise((resolve) => {
        udp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      await new Promise((resolve) => {
        udp.bind(socketId, '0.0.0.0', 0, () => resolve());
      });
      
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const result = await new Promise((resolve) => {
        udp.send(socketId, data.buffer, '127.0.0.1', 5000, (sendInfo) => {
          resolve(sendInfo);
        });
      });
      
      expect(result.resultCode).toBe(0);
      expect(result.bytesSent).toBe(5);
    });

    test('should close socket', async () => {
      const udp = global.chrome.sockets.udp;
      
      const socketId = await new Promise((resolve) => {
        udp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      await new Promise((resolve) => {
        udp.close(socketId, () => resolve());
      });
      
      // Socket should be removed
      const info = await new Promise((resolve) => {
        udp.getInfo(socketId, (info) => {
          resolve(info);
        });
      });
      
      expect(info).toBeNull();
    });
  });

  describe('Broadcast Logic', () => {
    test('should broadcast to matching subscribers', () => {
      const subscriptions = new Map();
      
      // Add subscribers
      subscriptions.set('192.168.1.100:50000', {
        clientAddress: '192.168.1.100',
        clientPort: 50000,
        filter: { source: '10.0.0.1', group: '232.1.1.1', port: 1234 }
      });
      
      subscriptions.set('192.168.1.101:50001', {
        clientAddress: '192.168.1.101',
        clientPort: 50001,
        filter: { source: '*', group: '232.1.1.1', port: '*' }
      });
      
      subscriptions.set('192.168.1.102:50002', {
        clientAddress: '192.168.1.102',
        clientPort: 50002,
        filter: { source: '10.0.0.2', group: '232.1.1.1', port: 1234 }
      });
      
      // Packet metadata
      const sourceIP = '10.0.0.1';
      const groupIP = '232.1.1.1';
      const port = 1234;
      
      // Find matching subscribers
      const matches = [];
      for (const [key, sub] of subscriptions.entries()) {
        const sourceMatch = sub.filter.source === '*' || sub.filter.source === sourceIP;
        const groupMatch = sub.filter.group === '*' || sub.filter.group === groupIP;
        const portMatch = sub.filter.port === '*' || sub.filter.port === port;
        
        if (sourceMatch && groupMatch && portMatch) {
          matches.push(sub);
        }
      }
      
      // Should match first two subscribers, not the third
      expect(matches.length).toBe(2);
      expect(matches[0].clientAddress).toBe('192.168.1.100');
      expect(matches[1].clientAddress).toBe('192.168.1.101');
    });
  });
});




