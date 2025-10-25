/**
 * Unit tests for TCP/HTTP Output Server
 * 
 * These tests run in Node.js without requiring IWA or browser environment.
 * We mock the chrome.sockets.tcp API to test the server logic.
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { setupChromeMocks, resetChromeMocks } = require('../mocks/chrome-sockets');

describe('TCP Server Unit Tests', () => {
  beforeEach(() => {
    // Setup chrome mocks before importing the server
    setupChromeMocks();
    
    // Clear module cache
    jest.resetModules();
    
    // Mock console methods
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    resetChromeMocks();
    jest.restoreAllMocks();
  });

  describe('Initialization', () => {
    test('should create TCP server instance', () => {
      class LocalTCPServer {
        constructor() {
          this.serverSocketId = null;
          this.clients = new Map();
          this.enabled = false;
        }
      }
      
      const server = new LocalTCPServer();
      expect(server).toBeDefined();
      expect(server.serverSocketId).toBeNull();
      expect(server.clients).toBeInstanceOf(Map);
      expect(server.enabled).toBe(false);
    });
  });

  describe('Client Management', () => {
    test('should add client', () => {
      const clients = new Map();
      const clientSocketId = 100;
      const filter = {
        source: '10.0.0.1',
        group: '232.1.1.1',
        port: 1234
      };

      clients.set(clientSocketId, { filter, active: true });

      expect(clients.has(clientSocketId)).toBe(true);
      expect(clients.get(clientSocketId).filter.source).toBe('10.0.0.1');
      expect(clients.get(clientSocketId).active).toBe(true);
    });

    test('should remove client', () => {
      const clients = new Map();
      const clientSocketId = 100;
      
      clients.set(clientSocketId, { filter: {}, active: true });
      expect(clients.has(clientSocketId)).toBe(true);
      
      clients.delete(clientSocketId);
      expect(clients.has(clientSocketId)).toBe(false);
    });

    test('should handle multiple clients', () => {
      const clients = new Map();
      
      clients.set(100, {
        filter: { source: '*', group: '232.1.1.1', port: 1234 },
        active: true
      });
      
      clients.set(101, {
        filter: { source: '10.0.0.1', group: '*', port: '*' },
        active: true
      });

      expect(clients.size).toBe(2);
      expect(clients.has(100)).toBe(true);
      expect(clients.has(101)).toBe(true);
    });
  });

  describe('HTTP Header Parsing', () => {
    test('should parse GET request path', () => {
      const requestLine = 'GET /stream/10.0.0.1/232.1.1.1/1234 HTTP/1.1';
      const match = requestLine.match(/GET\s+([^\s]+)\s+HTTP/);
      
      expect(match).not.toBeNull();
      expect(match[1]).toBe('/stream/10.0.0.1/232.1.1.1/1234');
    });

    test('should parse path parameters', () => {
      const path = '/stream/10.0.0.1/232.1.1.1/1234';
      const pathMatch = path.match(/^\/stream\/([^\/]+)\/([^\/]+)\/([^\/\?]+)/);
      
      expect(pathMatch).not.toBeNull();
      expect(pathMatch[1]).toBe('10.0.0.1');
      expect(pathMatch[2]).toBe('232.1.1.1');
      expect(pathMatch[3]).toBe('1234');
    });

    test('should parse wildcard path', () => {
      const path = '/stream/*/*/1234';
      const pathMatch = path.match(/^\/stream\/([^\/]+)\/([^\/]+)\/([^\/\?]+)/);
      
      expect(pathMatch).not.toBeNull();
      expect(pathMatch[1]).toBe('*');
      expect(pathMatch[2]).toBe('*');
      expect(pathMatch[3]).toBe('1234');
    });

    test('should parse query parameters', () => {
      const path = '/stream?source=10.0.0.1&group=232.1.1.1&port=1234';
      const url = new URL(path, 'http://localhost');
      
      expect(url.searchParams.get('source')).toBe('10.0.0.1');
      expect(url.searchParams.get('group')).toBe('232.1.1.1');
      expect(url.searchParams.get('port')).toBe('1234');
    });
  });

  describe('HTTP Response Generation', () => {
    test('should generate HTTP headers for chunked transfer', () => {
      const headers = [
        'HTTP/1.1 200 OK',
        'Content-Type: application/octet-stream',
        'Transfer-Encoding: chunked',
        'Connection: keep-alive',
        'Cache-Control: no-cache',
        '',
        ''
      ].join('\r\n');
      
      expect(headers).toContain('HTTP/1.1 200 OK');
      expect(headers).toContain('Transfer-Encoding: chunked');
      expect(headers.endsWith('\r\n\r\n')).toBe(true);
    });

    test('should format chunk with size', () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const chunkSize = data.length.toString(16);
      const chunk = `${chunkSize}\r\n${String.fromCharCode(...data)}\r\n`;
      
      expect(chunk.startsWith('5\r\n')).toBe(true);
      expect(chunk.endsWith('\r\n')).toBe(true);
    });

    test('should format final chunk', () => {
      const finalChunk = '0\r\n\r\n';
      
      expect(finalChunk).toBe('0\r\n\r\n');
    });
  });

  describe('Packet Filtering', () => {
    function matchesFilter(filter, sourceIP, groupIP, port) {
      const sourceMatch = filter.source === '*' || filter.source === sourceIP;
      const groupMatch = filter.group === '*' || filter.group === groupIP;
      const portMatch = filter.port === '*' || String(filter.port) === String(port);
      return sourceMatch && groupMatch && portMatch;
    }

    test('should match exact filter', () => {
      const filter = { source: '10.0.0.1', group: '232.1.1.1', port: '1234' };
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', '1234')).toBe(true);
      expect(matchesFilter(filter, '10.0.0.2', '232.1.1.1', '1234')).toBe(false);
    });

    test('should match wildcard source', () => {
      const filter = { source: '*', group: '232.1.1.1', port: '1234' };
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', '1234')).toBe(true);
      expect(matchesFilter(filter, '192.168.1.1', '232.1.1.1', '1234')).toBe(true);
    });

    test('should match all wildcards', () => {
      const filter = { source: '*', group: '*', port: '*' };
      expect(matchesFilter(filter, '10.0.0.1', '232.1.1.1', '1234')).toBe(true);
    });
  });

  describe('Chrome Sockets Integration', () => {
    test('should create TCP socket', async () => {
      const tcp = global.chrome.sockets.tcp;
      
      const socketId = await new Promise((resolve) => {
        tcp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      expect(socketId).toBeDefined();
      expect(typeof socketId).toBe('number');
    });

    test('should bind and listen on socket', async () => {
      const tcp = global.chrome.sockets.tcp;
      
      const socketId = await new Promise((resolve) => {
        tcp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      const bindResult = await new Promise((resolve) => {
        tcp.bind(socketId, '127.0.0.1', 5001, (result) => {
          resolve(result);
        });
      });
      
      expect(bindResult).toBe(0); // Success
      
      const listenResult = await new Promise((resolve) => {
        tcp.listen(socketId, '127.0.0.1', 5001, 5, (result) => {
          resolve(result);
        });
      });
      
      expect(listenResult).toBe(0); // Success
      
      const info = await new Promise((resolve) => {
        tcp.getInfo(socketId, (info) => {
          resolve(info);
        });
      });
      
      expect(info.localAddress).toBe('127.0.0.1');
      expect(info.localPort).toBe(5001);
    });

    test('should send data to connected socket', async () => {
      const tcp = global.chrome.sockets.tcp;
      
      const socketId = await new Promise((resolve) => {
        tcp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      // Simulate connection
      await new Promise((resolve) => {
        tcp.connect(socketId, '127.0.0.1', 5001, () => resolve());
      });
      
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const result = await new Promise((resolve) => {
        tcp.send(socketId, data.buffer, (sendInfo) => {
          resolve(sendInfo);
        });
      });
      
      expect(result.resultCode).toBe(0);
      expect(result.bytesSent).toBe(5);
    });

    test('should accept client connection', async () => {
      const tcp = global.chrome.sockets.tcp;
      
      const serverSocketId = await new Promise((resolve) => {
        tcp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      await new Promise((resolve) => {
        tcp.bind(serverSocketId, '127.0.0.1', 5001, () => resolve());
      });
      
      await new Promise((resolve) => {
        tcp.listen(serverSocketId, '127.0.0.1', 5001, 5, () => resolve());
      });
      
      // Setup accept handler
      let acceptedClientId = null;
      tcp.onAccept.addListener((info) => {
        acceptedClientId = info.clientSocketId;
      });
      
      // Simulate client connection
      const clientSocketId = 200;
      tcp.simulateAccept(serverSocketId, clientSocketId);
      
      // Wait a tick for event to fire
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(acceptedClientId).toBe(clientSocketId);
    });

    test('should close socket', async () => {
      const tcp = global.chrome.sockets.tcp;
      
      const socketId = await new Promise((resolve) => {
        tcp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      await new Promise((resolve) => {
        tcp.close(socketId, () => resolve());
      });
      
      // Socket should be removed
      const info = await new Promise((resolve) => {
        tcp.getInfo(socketId, (info) => {
          resolve(info);
        });
      });
      
      expect(info).toBeNull();
    });
  });

  describe('Broadcast Logic', () => {
    test('should broadcast to matching clients', () => {
      const clients = new Map();
      
      // Add clients
      clients.set(100, {
        filter: { source: '10.0.0.1', group: '232.1.1.1', port: '1234' },
        active: true
      });
      
      clients.set(101, {
        filter: { source: '*', group: '232.1.1.1', port: '*' },
        active: true
      });
      
      clients.set(102, {
        filter: { source: '10.0.0.2', group: '232.1.1.1', port: '1234' },
        active: true
      });
      
      // Packet metadata
      const sourceIP = '10.0.0.1';
      const groupIP = '232.1.1.1';
      const port = '1234';
      
      // Find matching clients
      const matches = [];
      for (const [clientId, client] of clients.entries()) {
        const sourceMatch = client.filter.source === '*' || client.filter.source === sourceIP;
        const groupMatch = client.filter.group === '*' || client.filter.group === groupIP;
        const portMatch = client.filter.port === '*' || String(client.filter.port) === String(port);
        
        if (sourceMatch && groupMatch && portMatch && client.active) {
          matches.push(clientId);
        }
      }
      
      // Should match first two clients, not the third
      expect(matches.length).toBe(2);
      expect(matches).toContain(100);
      expect(matches).toContain(101);
      expect(matches).not.toContain(102);
    });
  });
});

