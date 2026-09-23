/**
 * Unit tests for the UDP Output Server (output-servers/udp-server.js).
 *
 * The suite loads the real module and replaces only the Direct Sockets API
 * with a double. The double hands back Node's own web streams, so the
 * WritableStream locking rules are the real ones: a second getWriter() on the
 * control socket's writable throws, exactly as it does in Chrome.
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { LocalUDPServer } = require('../../output-servers/udp-server.js');

// Every datagram written to any fake socket, in order.
let sent;

class FakeUDPSocket {
  constructor(options) {
    this.options = options;
    this.opened = Promise.resolve({
      localAddress: options.localAddress,
      localPort: options.localPort,
      readable: new ReadableStream({ pull() {} }),
      writable: new WritableStream({ write(message) { sent.push(message); } })
    });
  }

  async close() {}
}

describe('LocalUDPServer', () => {
  let server;

  beforeEach(() => {
    sent = [];
    global.UDPSocket = FakeUDPSocket;
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    server = new LocalUDPServer();
  });

  afterEach(async () => {
    await server.stop();
    delete global.UDPSocket;
    jest.restoreAllMocks();
  });

  test('start() binds the control socket and enables the server', async () => {
    await server.start(5000);

    expect(server.controlSocket.options).toEqual({ localAddress: '127.0.0.1', localPort: 5000 });
    expect(server.enabled).toBe(true);
    expect(server.dataPort).toBe(5000);
  });

  test('addSubscription delivers the ACK to the subscriber', async () => {
    await server.start(5000);

    await server.addSubscription(
      '192.168.1.100:50000',
      { source: '10.0.0.1', group: '232.1.1.1', port: 1234 },
      '192.168.1.100',
      50000
    );

    expect(sent).toHaveLength(1);
    expect(sent[0].remoteAddress).toBe('192.168.1.100');
    expect(sent[0].remotePort).toBe(50000);
    expect(JSON.parse(new TextDecoder().decode(sent[0].data))).toEqual({
      type: 'ACK',
      subscribed: { source: '10.0.0.1', group: '232.1.1.1', port: 1234 },
      dataPort: 5000
    });
    expect(server.getStatus().subscriptions).toBe(1);
  });

  test('broadcastPacket writes the payload to every matching subscriber', async () => {
    await server.start(5000);
    await server.addSubscription('a', { source: '10.0.0.1', group: '232.1.1.1', port: 1234 }, '192.168.1.100', 50000);
    await server.addSubscription('b', { group: '232.1.1.1', port: '*' }, '192.168.1.101', 50001);
    await server.addSubscription('c', { source: '10.0.0.2', group: '232.1.1.1', port: 1234 }, '192.168.1.102', 50002);
    sent.length = 0; // drop the three ACKs

    // A view with a non-zero offset: only the viewed bytes may go out.
    const payload = new Uint8Array([9, 1, 2, 3]).subarray(1);
    const count = await server.broadcastPacket(payload, '10.0.0.1', '232.1.1.1', 1234);

    expect(count).toBe(2);
    expect(sent.map(m => [m.remoteAddress, m.remotePort])).toEqual([
      ['192.168.1.100', 50000],
      ['192.168.1.101', 50001]
    ]);
    for (const message of sent) {
      expect(Array.from(new Uint8Array(message.data))).toEqual([1, 2, 3]);
    }
  });

  test('removeSubscription drops only the matching filter', async () => {
    await server.start(5000);
    await server.addSubscription('k', { source: '10.0.0.1', group: '232.1.1.1', port: 1 }, '1.1.1.1', 1);
    await server.addSubscription('k', { source: '10.0.0.1', group: '232.1.1.2', port: 1 }, '1.1.1.1', 1);

    server.removeSubscription('k', { source: '10.0.0.1', group: '232.1.1.1' });
    expect(server.subscriptions.get('k').map(f => f.group)).toEqual(['232.1.1.2']);

    server.removeSubscription('k', { source: '10.0.0.1', group: '232.1.1.2' });
    expect(server.subscriptions.has('k')).toBe(false);
  });

  describe('matchesFilter', () => {
    const match = (filter, port = 1234) =>
      server.matchesFilter(filter, '10.0.0.1', '232.1.1.1', port);

    test('exact filter matches only its own source, group and port', () => {
      const filter = { source: '10.0.0.1', group: '232.1.1.1', port: 1234 };
      expect(match(filter)).toBe(true);
      expect(server.matchesFilter(filter, '10.0.0.2', '232.1.1.1', 1234)).toBe(false);
      expect(server.matchesFilter(filter, '10.0.0.1', '232.1.1.2', 1234)).toBe(false);
      expect(match(filter, 5678)).toBe(false);
    });

    test('wildcards match anything', () => {
      expect(match({ source: '*', group: '*', port: '*' }, 9999)).toBe(true);
    });

    test('a missing port matches every port', () => {
      expect(match({ source: '10.0.0.1', group: '232.1.1.1' }, 5678)).toBe(true);
    });

    test('a port that arrived as a string still matches the numeric port', () => {
      expect(match({ source: '10.0.0.1', group: '232.1.1.1', port: '1234' })).toBe(true);
    });
  });

  test('broadcastPacket sends nothing when the server is not started', async () => {
    server.subscriptions.set('a', [{ source: '*', group: '*', port: '*', clientAddress: 'x', clientPort: 1 }]);

    expect(await server.broadcastPacket(new Uint8Array([1]), '10.0.0.1', '232.1.1.1', 1)).toBe(0);

    server.enabled = true; // enabled but no writer
    expect(await server.broadcastPacket(new Uint8Array([1]), '10.0.0.1', '232.1.1.1', 1)).toBe(0);
    server.enabled = false;
    expect(sent).toHaveLength(0);
  });

  test('getStatus reports the server shape', () => {
    expect(server.getStatus()).toEqual({
      enabled: false,
      controlPort: 5000,
      dataPort: 0,
      subscriptions: 0
    });
  });
});
