/**
 * Unit tests for the Subscription Manager (output-servers/subscription-manager.js).
 *
 * The manager is pure bookkeeping, so the suite loads the real class and
 * asserts on its methods directly.
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const { SubscriptionManager } = require('../../output-servers/subscription-manager.js');

const sub = (overrides = {}) => ({
  source: '10.0.0.1',
  group: '232.1.1.1',
  port: 1234,
  protocol: 'udp',
  ...overrides
});

describe('SubscriptionManager', () => {
  let manager;

  beforeEach(() => {
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    manager = new SubscriptionManager();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('addSubscription', () => {
    test('stores the subscription and indexes an exact stream', () => {
      expect(manager.addSubscription('client-1', sub())).toBe(true);

      expect(manager.getSubscription('client-1')).toEqual(expect.objectContaining({ ...sub(), id: 'client-1' }));
      expect(Array.from(manager.streamSubscribers.get('10.0.0.1:232.1.1.1:1234'))).toEqual(['client-1']);
    });

    test('does not index a wildcard subscription', () => {
      expect(manager.addSubscription('client-1', sub({ source: '*', port: '*' }))).toBe(true);

      expect(manager.streamSubscribers.size).toBe(0);
    });

    test('replaces an existing subscription for the same subscriber', () => {
      manager.addSubscription('client-1', sub());
      manager.addSubscription('client-1', sub({ group: '232.1.1.2' }));

      expect(manager.getAllSubscriptions()).toHaveLength(1);
      expect(manager.getSubscription('client-1').group).toBe('232.1.1.2');
      expect(Array.from(manager.streamSubscribers.keys())).toEqual(['10.0.0.1:232.1.1.2:1234']);
    });

    test.each([
      ['a malformed source', { source: 'invalid' }],
      ['a unicast group', { group: '192.168.1.1' }],
      ['port 0', { port: 0 }],
      ['port 65536', { port: 65536 }],
      ['no protocol', { protocol: undefined }]
    ])('rejects %s', (_label, overrides) => {
      expect(manager.addSubscription('client-1', sub(overrides))).toBe(false);
      expect(manager.getAllSubscriptions()).toHaveLength(0);
    });
  });

  test('removeSubscription removes the subscriber and its empty stream entry', () => {
    manager.addSubscription('client-1', sub());

    expect(manager.removeSubscription('client-1')).toBe(true);
    expect(manager.getSubscription('client-1')).toBeNull();
    expect(manager.streamSubscribers.size).toBe(0);
    expect(manager.removeSubscription('client-1')).toBe(false);
  });

  test('getSubscribersForStream applies wildcards and compares ports as strings', () => {
    manager.addSubscription('exact', sub());
    manager.addSubscription('any-source', sub({ source: '*', port: '*' }));
    manager.addSubscription('other-source', sub({ source: '10.0.0.2' }));
    manager.addSubscription('everything', sub({ source: '*', group: '*', port: '*' }));

    const ids = manager.getSubscribersForStream('10.0.0.1', '232.1.1.1', '1234').map(s => s.id);

    expect(ids.sort()).toEqual(['any-source', 'everything', 'exact']);
  });

  test('stats count subscriptions by protocol and clear() resets them', () => {
    manager.addSubscription('udp-1', sub());
    manager.addSubscription('udp-2', sub({ port: 5678 }));
    manager.addSubscription('tcp-1', sub({ protocol: 'tcp' }));

    expect(manager.getSubscriptionsByProtocol('udp').map(s => s.id)).toEqual(['udp-1', 'udp-2']);
    expect(manager.getStats()).toEqual(expect.objectContaining({
      totalSubscriptions: 3,
      totalStreams: 2,
      subscriptionsByProtocol: { udp: 2, tcp: 1 }
    }));

    manager.clear();

    expect(manager.getStatus()).toEqual(expect.objectContaining({ subscriptions: 0, streams: 0 }));
  });
});
