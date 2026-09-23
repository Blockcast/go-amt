/**
 * Unit tests for the TCP/HTTP Output Server (output-servers/tcp-server.js).
 *
 * The suite loads the real module and replaces only the Direct Sockets API
 * (TCPServerSocket and the accepted client sockets) with doubles built on
 * Node's own web streams, so every byte the server writes is recorded.
 */

const { isIP } = require('node:net');
const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { LocalTCPServer } = require('../../output-servers/tcp-server.js');

const encoder = new TextEncoder();
const text = (chunk) => new TextDecoder().decode(chunk);

// Shaped like the WICG Direct Sockets constructor:
//   constructor(DOMString localAddress, optional TCPServerSocketOptions options = {})
// A non-IP localAddress or localPort 0 throws TypeError synchronously, and a
// localPort below 32678 rejects `opened` with NotAllowedError, as the spec does.
class FakeTCPServerSocket {
  constructor(localAddress, options = {}) {
    if (typeof localAddress !== 'string' || isIP(localAddress) === 0) {
      throw new TypeError(`TCPServerSocket: localAddress ${JSON.stringify(localAddress)} is not an IP address`);
    }
    if (options.localPort === 0) throw new TypeError('TCPServerSocket: localPort must not be 0');
    this.localAddress = localAddress;
    this.port = options.localPort;
    this.opened = options.localPort !== undefined && options.localPort < 32678
      ? Promise.reject(new DOMException('TCPServerSocket: localPort below 32678', 'NotAllowedError'))
      : Promise.resolve({ localAddress, localPort: options.localPort, readable: new ReadableStream({ pull() {} }) });
    this.opened.catch(() => {});
  }

  async close() {}
}

// Opens the server socket the way the spec requires and starts accepting,
// so the tests below exercise production code past start().
function openServer(server) {
  server.serverSocket = new TCPServerSocket('127.0.0.1', { localPort: 40001 });
  server.enabled = true;
  server.acceptConnections();
}

// An accepted connection that sends `request` and records what it receives.
// `failAfter` makes every write after the first N reject, like a reset peer.
function fakeClient(request, { failAfter = Infinity } = {}) {
  const written = [];
  return {
    written,
    closed: new Promise(() => {}),
    close: async () => {},
    opened: Promise.resolve({
      readable: new ReadableStream({
        start(controller) { controller.enqueue(encoder.encode(request)); }
      }),
      writable: new WritableStream({
        write(chunk) {
          if (written.length >= failAfter) throw new Error('connection reset');
          written.push(chunk);
        }
      })
    })
  };
}

const get = (path) => `GET ${path} HTTP/1.1\r\nHost: localhost\r\n\r\n`;

describe('LocalTCPServer', () => {
  let server;

  beforeEach(() => {
    global.TCPServerSocket = FakeTCPServerSocket;
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    server = new LocalTCPServer();
  });

  afterEach(async () => {
    await server.stop();
    delete global.TCPServerSocket;
    jest.restoreAllMocks();
  });

  // Known break: tcp-server.js:25 calls new TCPServerSocket(port), which the
  // spec rejects because "5001" is not an IP address. Flip this test when
  // start() passes (localAddress, { localPort }).
  test('start() is rejected by a spec-conformant TCPServerSocket (known break)', async () => {
    await expect(server.start(5001)).rejects.toThrow(TypeError);
    expect(server.enabled).toBe(false);
  });

  describe('parseFilter', () => {
    test('reads source, group and port from the path', () => {
      expect(server.parseFilter('/stream/10.0.0.1/232.1.1.1/1234'))
        .toEqual({ source: '10.0.0.1', group: '232.1.1.1', port: 1234 });
    });

    test('maps * path segments to wildcards', () => {
      expect(server.parseFilter('/stream/*/*/*')).toEqual({ source: '*', group: '*', port: '*' });
    });

    test('reads the query form and leaves an absent port as a wildcard', () => {
      expect(server.parseFilter('/stream?source=10.0.0.1&group=232.1.1.1&port=5000'))
        .toEqual({ source: '10.0.0.1', group: '232.1.1.1', port: 5000 });
      expect(server.parseFilter('/stream?group=232.1.1.1'))
        .toEqual({ source: '*', group: '232.1.1.1', port: '*' });
    });

    test('returns all wildcards for an unrecognised path', () => {
      expect(server.parseFilter('/')).toEqual({ source: '*', group: '*', port: '*' });
    });
  });

  describe('matchesFilter', () => {
    test('exact filter matches only its own source, group and port', () => {
      const filter = { source: '10.0.0.1', group: '232.1.1.1', port: 1234 };
      expect(server.matchesFilter(filter, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(server.matchesFilter(filter, '10.0.0.2', '232.1.1.1', 1234)).toBe(false);
      expect(server.matchesFilter(filter, '10.0.0.1', '232.1.1.2', 1234)).toBe(false);
      expect(server.matchesFilter(filter, '10.0.0.1', '232.1.1.1', 5678)).toBe(false);
    });

    test('wildcards match anything and a string port matches its number', () => {
      expect(server.matchesFilter({ source: '*', group: '*', port: '*' }, '1.2.3.4', '239.0.0.1', 9)).toBe(true);
      expect(server.matchesFilter({ source: '*', group: '*', port: '1234' }, '1.2.3.4', '239.0.0.1', 1234)).toBe(true);
    });
  });

  test('handleConnection answers with chunked headers and registers the filter', async () => {
    const client = fakeClient(get('/stream/10.0.0.1/232.1.1.1/1234'));

    await server.handleConnection(client);

    const headers = text(client.written[0]);
    expect(headers.startsWith('HTTP/1.1 200 OK\r\n')).toBe(true);
    expect(headers).toContain('Transfer-Encoding: chunked\r\n');
    expect(headers).toContain('X-Stream-Source: 10.0.0.1\r\n');
    expect(headers).toContain('X-Stream-Group: 232.1.1.1\r\n');
    expect(headers).toContain('X-Stream-Port: 1234\r\n');
    expect(headers.endsWith('\r\n\r\n')).toBe(true);
    expect(server.clients.get(1).filter).toEqual({ source: '10.0.0.1', group: '232.1.1.1', port: 1234 });
  });

  test('broadcastPacket sends one HTTP chunk to each matching client', async () => {
    openServer(server);
    const matching = fakeClient(get('/stream/10.0.0.1/232.1.1.1/1234'));
    const other = fakeClient(get('/stream/10.0.0.2/232.1.1.1/1234'));
    await server.handleConnection(matching);
    await server.handleConnection(other);

    const count = await server.broadcastPacket(new Uint8Array([1, 2, 3]), '10.0.0.1', '232.1.1.1', 1234);

    expect(count).toBe(1);
    expect(matching.written.slice(1).map(c => Array.from(new Uint8Array(c)))).toEqual([
      Array.from(encoder.encode('3\r\n')),
      [1, 2, 3],
      Array.from(encoder.encode('\r\n'))
    ]);
    expect(other.written).toHaveLength(1); // headers only
  });

  test('a failed chunk write closes and forgets the client', async () => {
    openServer(server);
    const client = fakeClient(get('/stream/*/*/*'), { failAfter: 1 });
    await server.handleConnection(client);

    await server.sendChunk(1, new Uint8Array([1]));

    expect(server.clients.has(1)).toBe(false);
  });

  test('broadcastPacket sends nothing when the server is not started', async () => {
    const client = fakeClient(get('/stream/*/*/*'));
    await server.handleConnection(client);

    expect(await server.broadcastPacket(new Uint8Array([1]), '10.0.0.1', '232.1.1.1', 1)).toBe(0);
    expect(client.written).toHaveLength(1);
  });

  test('getStatus reports the server shape', () => {
    expect(server.getStatus()).toEqual({ enabled: false, port: 5001, clients: 0 });
  });
});
