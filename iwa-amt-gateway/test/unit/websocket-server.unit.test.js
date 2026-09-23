/**
 * Unit tests for the WebSocket Output Server (output-servers/websocket-server.js).
 *
 * The suite loads the real module. This server is the one output server built
 * on chrome.sockets.tcp rather than Direct Sockets, so it keeps the
 * chrome.sockets mock and records every byte the server hands to
 * chrome.sockets.tcp.send.
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { setupChromeMocks } = require('../mocks/chrome-sockets');
const { LocalWebSocketServer } = require('../../output-servers/websocket-server.js');

const encoder = new TextEncoder();
const CLIENT = 200;

// RFC 6455 section 1.3 sample key and the accept value it must produce.
const SAMPLE_KEY = 'dGhlIHNhbXBsZSBub25jZQ==';
const SAMPLE_ACCEPT = 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=';

const upgradeRequest = (headers = ['Upgrade: websocket', `Sec-WebSocket-Key: ${SAMPLE_KEY}`]) =>
  encoder.encode(['GET /stream HTTP/1.1', 'Host: localhost:5002', ...headers, '', ''].join('\r\n'));

// A client-to-server frame: always masked, payload under 126 bytes.
function maskedFrame(opcode, payload, mask = [0x37, 0xfa, 0x21, 0x3d]) {
  const frame = new Uint8Array(6 + payload.length);
  frame[0] = 0x80 | opcode;
  frame[1] = 0x80 | payload.length;
  frame.set(mask, 2);
  payload.forEach((byte, i) => { frame[6 + i] = byte ^ mask[i % 4]; });
  return frame;
}

describe('LocalWebSocketServer', () => {
  let server;
  let sent; // byte arrays passed to chrome.sockets.tcp.send, in order

  beforeEach(async () => {
    setupChromeMocks();
    global.chrome.runtime = {};
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});

    sent = [];
    const tcp = global.chrome.sockets.tcp;
    const send = tcp.send.bind(tcp);
    tcp.send = (socketId, buffer, callback) => {
      sent.push(Array.from(new Uint8Array(buffer)));
      send(socketId, buffer, callback);
    };

    server = new LocalWebSocketServer();
  });

  afterEach(async () => {
    await server.stop();
    delete global.chrome;
    jest.restoreAllMocks();
  });

  // Start the server, accept one client and complete its handshake.
  async function connectClient() {
    await server.start(5002, '127.0.0.1');
    global.chrome.sockets.tcp.simulateAccept(server.serverSocketId, CLIENT);
    await server.handleClientData(CLIENT, upgradeRequest());
  }

  test('start() binds, listens and enables the server', async () => {
    await server.start(5002, '127.0.0.1');

    const info = global.chrome.sockets.tcp.getSocket(server.serverSocketId).getInfo();
    expect(info).toEqual(expect.objectContaining({ localAddress: '127.0.0.1', localPort: 5002 }));
    expect(server.enabled).toBe(true);
    expect(server.isHealthy()).toBe(true);
  });

  test('an accepted client completes the RFC 6455 handshake', async () => {
    await server.start(5002, '127.0.0.1');
    global.chrome.sockets.tcp.simulateAccept(server.serverSocketId, CLIENT);
    expect(server.clients.get(CLIENT).state).toBe('handshake');

    await server.handleClientData(CLIENT, upgradeRequest());

    const response = new TextDecoder().decode(new Uint8Array(sent[0]));
    expect(response.startsWith('HTTP/1.1 101 Switching Protocols\r\n')).toBe(true);
    expect(response).toContain(`Sec-WebSocket-Accept: ${SAMPLE_ACCEPT}\r\n`);
    expect(server.clients.get(CLIENT).state).toBe('connected');
    expect(server.stats.activeConnections).toBe(1);
  });

  test('an upgrade request without the WebSocket headers closes the client', async () => {
    await server.start(5002, '127.0.0.1');
    global.chrome.sockets.tcp.simulateAccept(server.serverSocketId, CLIENT);

    await server.handleClientData(CLIENT, upgradeRequest(['Connection: keep-alive']));

    expect(server.clients.has(CLIENT)).toBe(false);
    expect(sent).toHaveLength(0);
  });

  test('a subscribe message sets the filter that broadcastPacket applies', async () => {
    await connectClient();
    const subscribe = { type: 'subscribe', source: '10.0.0.1', group: '232.1.1.1', port: 1234 };

    await server.handleClientData(CLIENT, maskedFrame(0x1, encoder.encode(JSON.stringify(subscribe))));

    expect(server.clients.get(CLIENT).filter).toEqual({ source: '10.0.0.1', group: '232.1.1.1', port: 1234 });
    const reply = sent[sent.length - 1];
    expect(reply[0]).toBe(0x81);
    expect(JSON.parse(new TextDecoder().decode(new Uint8Array(reply.slice(2))))).toEqual({
      type: 'subscribed',
      filter: { source: '10.0.0.1', group: '232.1.1.1', port: 1234 }
    });

    expect(await server.broadcastPacket(new Uint8Array([1, 2, 3]), '10.0.0.1', '232.1.1.1', 1234)).toBe(1);
    expect(sent[sent.length - 1]).toEqual([0x82, 3, 1, 2, 3]);

    const before = sent.length;
    expect(await server.broadcastPacket(new Uint8Array([1]), '10.0.0.2', '232.1.1.1', 1234)).toBe(0);
    expect(sent).toHaveLength(before);
  });

  test('a ping frame is answered with a pong carrying the same payload', async () => {
    await connectClient();

    await server.handleClientData(CLIENT, maskedFrame(0x9, encoder.encode('hi')));

    expect(sent[sent.length - 1]).toEqual([0x8a, 2, 0x68, 0x69]);
  });

  test('unmaskPayload decodes the RFC 6455 masked "Hello" sample', () => {
    const masked = new Uint8Array([0x7f, 0x9f, 0x4d, 0x51, 0x58]);
    const key = new Uint8Array([0x37, 0xfa, 0x21, 0x3d]);

    expect(new TextDecoder().decode(server.unmaskPayload(masked, key))).toBe('Hello');
  });

  test('encodeFrame switches to the 16-bit length form at 126 bytes', () => {
    const frame = server.encodeFrame(0x82, new Uint8Array(300));

    expect(Array.from(frame.slice(0, 4))).toEqual([0x82, 126, 0x01, 0x2c]);
    expect(frame.length).toBe(304);
  });

  test('matchesFilter applies wildcards and compares ports as strings', () => {
    expect(server.matchesFilter({ source: '*', group: '*', port: '*' }, '1.2.3.4', '239.0.0.1', 9)).toBe(true);
    expect(server.matchesFilter({ source: '10.0.0.1', group: '232.1.1.1', port: '1234' }, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
    expect(server.matchesFilter({ source: '10.0.0.1', group: '232.1.1.1', port: 1234 }, '10.0.0.1', '232.1.1.1', 5678)).toBe(false);
  });

  test('broadcastPacket sends nothing when the server is not started', async () => {
    expect(await server.broadcastPacket(new Uint8Array([1]), '10.0.0.1', '232.1.1.1', 1)).toBe(0);
  });

  test('stop() closes the connected client and disables the server', async () => {
    await connectClient();

    await server.stop();

    expect(sent[sent.length - 1]).toEqual([0x88, 0]); // close frame
    expect(server.clients.size).toBe(0);
    expect(server.enabled).toBe(false);
    expect(server.getStatus()).toEqual(expect.objectContaining({ enabled: false, port: 5002, clients: 0 }));
  });
});
