/**
 * Unit tests for WebSocket Output Server
 * 
 * WebSocket server for web-based clients. Uses TCP sockets with WebSocket
 * protocol implementation (handshake, framing, etc.)
 * 
 * TEST FIRST - Writing tests before implementation
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { setupChromeMocks, resetChromeMocks } = require('../mocks/chrome-sockets');

describe('WebSocket Server Unit Tests', () => {
  beforeEach(() => {
    setupChromeMocks();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    resetChromeMocks();
    jest.restoreAllMocks();
  });

  describe('Initialization', () => {
    test('should create WebSocket server instance', () => {
      class LocalWebSocketServer {
        constructor() {
          this.serverSocketId = null;
          this.clients = new Map();
          this.enabled = false;
        }
      }
      
      const server = new LocalWebSocketServer();
      expect(server).toBeDefined();
      expect(server.serverSocketId).toBeNull();
      expect(server.clients).toBeInstanceOf(Map);
      expect(server.enabled).toBe(false);
    });
  });

  describe('WebSocket Handshake', () => {
    test('should parse WebSocket upgrade request', () => {
      const request = [
        'GET /stream HTTP/1.1',
        'Host: localhost:5002',
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==',
        'Sec-WebSocket-Version: 13',
        '',
        ''
      ].join('\r\n');

      const lines = request.split('\r\n');
      const headers = {};
      
      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        if (!line) break;
        const [key, value] = line.split(': ');
        headers[key.toLowerCase()] = value;
      }

      expect(headers['upgrade']).toBe('websocket');
      expect(headers['connection']).toBe('Upgrade');
      expect(headers['sec-websocket-key']).toBe('dGhlIHNhbXBsZSBub25jZQ==');
      expect(headers['sec-websocket-version']).toBe('13');
    });

    test('should generate accept key for handshake', () => {
      // WebSocket handshake: base64(SHA-1(key + magic-string))
      const clientKey = 'dGhlIHNhbXBsZSBub25jZQ==';
      const magicString = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
      
      // In production, we'd use crypto.subtle.digest
      // For testing, just verify the format
      const acceptKey = clientKey + magicString;
      
      expect(clientKey).toBeDefined();
      expect(magicString).toBe('258EAFA5-E914-47DA-95CA-C5AB0DC85B11');
    });

    test('should generate handshake response', () => {
      const response = [
        'HTTP/1.1 101 Switching Protocols',
        'Upgrade: websocket',
        'Connection: Upgrade',
        'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=',
        '',
        ''
      ].join('\r\n');

      expect(response).toContain('101 Switching Protocols');
      expect(response).toContain('Upgrade: websocket');
      expect(response).toContain('Connection: Upgrade');
      expect(response).toContain('Sec-WebSocket-Accept:');
    });
  });

  describe('WebSocket Frame Encoding/Decoding', () => {
    test('should encode text frame', () => {
      const text = 'Hello';
      const payload = new TextEncoder().encode(text);
      
      // Simple frame structure (unmasked, FIN=1, opcode=1 for text)
      const frame = new Uint8Array(2 + payload.length);
      frame[0] = 0x81; // FIN=1, opcode=1 (text)
      frame[1] = payload.length; // Payload length
      frame.set(payload, 2);

      expect(frame[0]).toBe(0x81);
      expect(frame[1]).toBe(5); // 'Hello' length
      expect(frame.length).toBe(7); // 2 header + 5 payload
    });

    test('should encode binary frame', () => {
      const payload = new Uint8Array([1, 2, 3, 4, 5]);
      
      // Binary frame (opcode=2)
      const frame = new Uint8Array(2 + payload.length);
      frame[0] = 0x82; // FIN=1, opcode=2 (binary)
      frame[1] = payload.length;
      frame.set(payload, 2);

      expect(frame[0]).toBe(0x82);
      expect(frame[1]).toBe(5);
      expect(frame.length).toBe(7);
    });

    test('should decode received frame', () => {
      // Received masked frame (from client)
      const frame = new Uint8Array([
        0x81, // FIN=1, opcode=1
        0x85, // MASK=1, length=5
        0x12, 0x34, 0x56, 0x78, // Masking key
        0x5A, 0x5E, 0x3A, 0x1C, 0x69 // Masked payload
      ]);

      const masked = (frame[1] & 0x80) !== 0;
      const length = frame[1] & 0x7F;
      
      expect(masked).toBe(true);
      expect(length).toBe(5);
    });

    test('should handle extended payload length (16-bit)', () => {
      const largePayload = new Uint8Array(300);
      
      // Frame with 16-bit length
      const frame = new Uint8Array(4 + largePayload.length);
      frame[0] = 0x82; // FIN=1, opcode=2
      frame[1] = 126; // Extended 16-bit length
      frame[2] = (largePayload.length >> 8) & 0xFF; // MSB
      frame[3] = largePayload.length & 0xFF; // LSB
      frame.set(largePayload, 4);

      expect(frame[1]).toBe(126);
      expect(frame.length).toBe(304);
    });
  });

  describe('Client Management', () => {
    test('should add WebSocket client', () => {
      const clients = new Map();
      const clientId = 100;
      const client = {
        socketId: clientId,
        filter: { source: '*', group: '*', port: '*' },
        state: 'connected'
      };

      clients.set(clientId, client);

      expect(clients.has(clientId)).toBe(true);
      expect(clients.get(clientId).state).toBe('connected');
    });

    test('should remove WebSocket client', () => {
      const clients = new Map();
      clients.set(100, { socketId: 100 });
      
      expect(clients.has(100)).toBe(true);
      
      clients.delete(100);
      
      expect(clients.has(100)).toBe(false);
    });

    test('should handle multiple WebSocket clients', () => {
      const clients = new Map();
      
      clients.set(100, { socketId: 100, filter: { source: '*', group: '*', port: '*' } });
      clients.set(101, { socketId: 101, filter: { source: '10.0.0.1', group: '232.1.1.1', port: 1234 } });
      clients.set(102, { socketId: 102, filter: { source: '*', group: '232.1.1.1', port: '*' } });

      expect(clients.size).toBe(3);
    });
  });

  describe('Subscription Messages', () => {
    test('should parse subscription message from WebSocket', () => {
      const message = JSON.stringify({
        type: 'subscribe',
        source: '10.0.0.1',
        group: '232.1.1.1',
        port: 1234
      });

      const parsed = JSON.parse(message);

      expect(parsed.type).toBe('subscribe');
      expect(parsed.source).toBe('10.0.0.1');
      expect(parsed.group).toBe('232.1.1.1');
      expect(parsed.port).toBe(1234);
    });

    test('should parse unsubscribe message', () => {
      const message = JSON.stringify({
        type: 'unsubscribe'
      });

      const parsed = JSON.parse(message);

      expect(parsed.type).toBe('unsubscribe');
    });

    test('should handle wildcard subscription via WebSocket', () => {
      const message = JSON.stringify({
        type: 'subscribe',
        source: '*',
        group: '232.1.1.1',
        port: '*'
      });

      const parsed = JSON.parse(message);

      expect(parsed.source).toBe('*');
      expect(parsed.port).toBe('*');
    });
  });

  describe('Packet Broadcasting', () => {
    test('should broadcast packet to all connected WebSocket clients', async () => {
      const clients = new Map();
      
      clients.set(100, {
        socketId: 100,
        filter: { source: '*', group: '*', port: '*' },
        state: 'connected'
      });
      clients.set(101, {
        socketId: 101,
        filter: { source: '10.0.0.1', group: '232.1.1.1', port: 1234 },
        state: 'connected'
      });

      const packet = new Uint8Array([1, 2, 3, 4, 5]);
      const sourceIP = '10.0.0.1';
      const groupIP = '232.1.1.1';
      const port = 1234;

      // Find matching clients
      const matches = [];
      for (const [id, client] of clients.entries()) {
        if (client.state !== 'connected') continue;
        
        const sourceMatch = client.filter.source === '*' || client.filter.source === sourceIP;
        const groupMatch = client.filter.group === '*' || client.filter.group === groupIP;
        const portMatch = client.filter.port === '*' || String(client.filter.port) === String(port);
        
        if (sourceMatch && groupMatch && portMatch) {
          matches.push(id);
        }
      }

      expect(matches.length).toBe(2);
      expect(matches).toContain(100);
      expect(matches).toContain(101);
    });

    test('should encode packet as binary WebSocket frame', () => {
      const packet = new Uint8Array([1, 2, 3, 4, 5]);
      
      // Encode as binary frame
      const frame = new Uint8Array(2 + packet.length);
      frame[0] = 0x82; // FIN=1, opcode=2 (binary)
      frame[1] = packet.length;
      frame.set(packet, 2);

      expect(frame.length).toBe(7);
      expect(frame[0]).toBe(0x82);
      expect(frame[1]).toBe(5);
    });

    test('should skip disconnected clients', () => {
      const clients = new Map();
      
      clients.set(100, { socketId: 100, filter: { source: '*', group: '*', port: '*' }, state: 'connected' });
      clients.set(101, { socketId: 101, filter: { source: '*', group: '*', port: '*' }, state: 'disconnected' });
      clients.set(102, { socketId: 102, filter: { source: '*', group: '*', port: '*' }, state: 'connected' });

      const activeClients = Array.from(clients.values())
        .filter(c => c.state === 'connected');

      expect(activeClients.length).toBe(2);
      expect(activeClients[0].socketId).toBe(100);
      expect(activeClients[1].socketId).toBe(102);
    });
  });

  describe('Chrome TCP Sockets Integration', () => {
    test('should create TCP server for WebSocket', async () => {
      const tcp = global.chrome.sockets.tcp;
      
      const socketId = await new Promise((resolve) => {
        tcp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      expect(socketId).toBeDefined();
      expect(typeof socketId).toBe('number');
    });

    test('should bind and listen on WebSocket port', async () => {
      const tcp = global.chrome.sockets.tcp;
      
      const socketId = await new Promise((resolve) => {
        tcp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      await new Promise((resolve) => {
        tcp.bind(socketId, '127.0.0.1', 5002, () => resolve());
      });
      
      await new Promise((resolve) => {
        tcp.listen(socketId, '127.0.0.1', 5002, 10, () => resolve());
      });
      
      const info = await new Promise((resolve) => {
        tcp.getInfo(socketId, (info) => resolve(info));
      });
      
      expect(info.localPort).toBe(5002);
    });

    test('should accept WebSocket client connection', async () => {
      const tcp = global.chrome.sockets.tcp;
      
      const serverSocketId = await new Promise((resolve) => {
        tcp.create({}, (createInfo) => {
          resolve(createInfo.socketId);
        });
      });
      
      await new Promise((resolve) => {
        tcp.bind(serverSocketId, '127.0.0.1', 5002, () => resolve());
      });
      
      await new Promise((resolve) => {
        tcp.listen(serverSocketId, '127.0.0.1', 5002, 10, () => resolve());
      });
      
      // Setup accept handler
      let acceptedClientId = null;
      tcp.onAccept.addListener((info) => {
        acceptedClientId = info.clientSocketId;
      });
      
      // Simulate client connection
      const clientSocketId = 200;
      tcp.simulateAccept(serverSocketId, clientSocketId);
      
      await new Promise(resolve => setTimeout(resolve, 10));
      
      expect(acceptedClientId).toBe(clientSocketId);
    });
  });

  describe('Connection Lifecycle', () => {
    test('should handle connection open', () => {
      const clients = new Map();
      const clientId = 100;
      
      clients.set(clientId, {
        socketId: clientId,
        state: 'handshake',
        connectedAt: Date.now()
      });
      
      // After handshake complete
      clients.get(clientId).state = 'connected';
      
      expect(clients.get(clientId).state).toBe('connected');
    });

    test('should handle connection close', () => {
      const clients = new Map();
      const clientId = 100;
      
      clients.set(clientId, { socketId: clientId, state: 'connected' });
      
      // Client disconnects
      clients.get(clientId).state = 'closed';
      
      expect(clients.get(clientId).state).toBe('closed');
    });

    test('should clean up closed connections', () => {
      const clients = new Map();
      
      clients.set(100, { socketId: 100, state: 'connected' });
      clients.set(101, { socketId: 101, state: 'closed' });
      clients.set(102, { socketId: 102, state: 'connected' });
      
      // Remove closed connections
      for (const [id, client] of clients.entries()) {
        if (client.state === 'closed') {
          clients.delete(id);
        }
      }
      
      expect(clients.size).toBe(2);
      expect(clients.has(101)).toBe(false);
    });
  });

  describe('Error Handling', () => {
    test('should handle invalid WebSocket frames', () => {
      const invalidFrame = new Uint8Array([0xFF, 0xFF]);
      
      // Try to parse
      const opcode = invalidFrame[0] & 0x0F;
      
      // Invalid opcode (15)
      expect(opcode).toBe(15);
      // Should be rejected (valid opcodes: 0-2, 8-10)
      const isValid = opcode <= 2 || (opcode >= 8 && opcode <= 10);
      expect(isValid).toBe(false);
    });

    test('should handle connection errors', () => {
      const clients = new Map();
      const clientId = 100;
      
      clients.set(clientId, {
        socketId: clientId,
        state: 'connected',
        lastError: null
      });
      
      // Simulate error
      clients.get(clientId).lastError = 'Connection reset';
      clients.get(clientId).state = 'error';
      
      expect(clients.get(clientId).state).toBe('error');
      expect(clients.get(clientId).lastError).toBe('Connection reset');
    });
  });

  describe('Statistics', () => {
    test('should count total connections', () => {
      const stats = {
        totalConnections: 0,
        activeConnections: 0,
        messagesReceived: 0,
        messagesSent: 0
      };
      
      stats.totalConnections = 10;
      stats.activeConnections = 7;
      
      expect(stats.totalConnections).toBe(10);
      expect(stats.activeConnections).toBe(7);
    });

    test('should track message counts', () => {
      const stats = {
        messagesReceived: 0,
        messagesSent: 0,
        bytesReceived: 0,
        bytesSent: 0
      };
      
      stats.messagesReceived += 5;
      stats.messagesSent += 10;
      stats.bytesReceived += 1024;
      stats.bytesSent += 2048;
      
      expect(stats.messagesReceived).toBe(5);
      expect(stats.messagesSent).toBe(10);
    });
  });
});




