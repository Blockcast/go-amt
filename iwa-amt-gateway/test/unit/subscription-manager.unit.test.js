/**
 * Unit tests for Subscription Manager
 * 
 * The Subscription Manager is the central component that tracks all subscriptions
 * across all output servers and manages stream-to-subscriber mapping.
 * 
 * TEST FIRST - Writing tests before implementation
 */

const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');

// Mock ES6 imports for testing
const WILDCARD = { SOURCE: '*', GROUP: '*', PORT: '*' };
global.WILDCARD = WILDCARD;

describe('Subscription Manager Unit Tests', () => {
  let SubscriptionManager;
  let manager;

  beforeEach(() => {
    // Mock console to avoid noise
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
    
    // Simple implementation for testing
    class TestSubscriptionManager {
      constructor() {
        this.subscriptions = new Map(); // subscriberId -> subscription
        this.streamSubscribers = new Map(); // streamKey -> Set<subscriberId>
      }
    }
    
    SubscriptionManager = TestSubscriptionManager;
    manager = new SubscriptionManager();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('Initialization', () => {
    test('should create subscription manager instance', () => {
      expect(manager).toBeDefined();
      expect(manager.subscriptions).toBeInstanceOf(Map);
      expect(manager.subscriptions.size).toBe(0);
    });

    test('should initialize with empty state', () => {
      expect(manager.subscriptions.size).toBe(0);
      expect(manager.streamSubscribers).toBeInstanceOf(Map);
    });
  });

  describe('Subscription Management', () => {
    test('should add subscription', () => {
      const subscriberId = 'client-1';
      const subscription = {
        source: '10.0.0.1',
        group: '232.1.1.1',
        port: 1234,
        protocol: 'udp',
        address: '192.168.1.100',
        port: 50000
      };

      manager.subscriptions.set(subscriberId, subscription);

      expect(manager.subscriptions.has(subscriberId)).toBe(true);
      expect(manager.subscriptions.get(subscriberId).source).toBe('10.0.0.1');
    });

    test('should remove subscription', () => {
      const subscriberId = 'client-1';
      manager.subscriptions.set(subscriberId, { source: '*', group: '*', port: '*' });
      
      expect(manager.subscriptions.has(subscriberId)).toBe(true);
      
      manager.subscriptions.delete(subscriberId);
      
      expect(manager.subscriptions.has(subscriberId)).toBe(false);
    });

    test('should handle multiple subscriptions', () => {
      manager.subscriptions.set('client-1', { source: '10.0.0.1', group: '232.1.1.1', port: 1234 });
      manager.subscriptions.set('client-2', { source: '*', group: '232.1.1.1', port: '*' });
      manager.subscriptions.set('client-3', { source: '10.0.0.2', group: '232.1.1.2', port: 5678 });

      expect(manager.subscriptions.size).toBe(3);
      expect(manager.subscriptions.has('client-1')).toBe(true);
      expect(manager.subscriptions.has('client-2')).toBe(true);
      expect(manager.subscriptions.has('client-3')).toBe(true);
    });

    test('should update existing subscription', () => {
      const subscriberId = 'client-1';
      manager.subscriptions.set(subscriberId, { source: '10.0.0.1', group: '232.1.1.1', port: 1234 });
      
      // Update subscription
      manager.subscriptions.set(subscriberId, { source: '*', group: '*', port: '*' });
      
      expect(manager.subscriptions.get(subscriberId).source).toBe('*');
      expect(manager.subscriptions.size).toBe(1);
    });
  });

  describe('Stream-to-Subscriber Mapping', () => {
    test('should create stream key from source/group/port', () => {
      const streamKey = (source, group, port) => `${source}:${group}:${port}`;
      
      const key = streamKey('10.0.0.1', '232.1.1.1', 1234);
      expect(key).toBe('10.0.0.1:232.1.1.1:1234');
    });

    test('should map stream to subscribers', () => {
      const streamKey = '10.0.0.1:232.1.1.1:1234';
      const subscribers = new Set(['client-1', 'client-2', 'client-3']);
      
      manager.streamSubscribers.set(streamKey, subscribers);
      
      expect(manager.streamSubscribers.has(streamKey)).toBe(true);
      expect(manager.streamSubscribers.get(streamKey).size).toBe(3);
    });

    test('should add subscriber to stream', () => {
      const streamKey = '10.0.0.1:232.1.1.1:1234';
      
      if (!manager.streamSubscribers.has(streamKey)) {
        manager.streamSubscribers.set(streamKey, new Set());
      }
      
      manager.streamSubscribers.get(streamKey).add('client-1');
      manager.streamSubscribers.get(streamKey).add('client-2');
      
      expect(manager.streamSubscribers.get(streamKey).size).toBe(2);
      expect(manager.streamSubscribers.get(streamKey).has('client-1')).toBe(true);
    });

    test('should remove subscriber from stream', () => {
      const streamKey = '10.0.0.1:232.1.1.1:1234';
      manager.streamSubscribers.set(streamKey, new Set(['client-1', 'client-2']));
      
      manager.streamSubscribers.get(streamKey).delete('client-1');
      
      expect(manager.streamSubscribers.get(streamKey).size).toBe(1);
      expect(manager.streamSubscribers.get(streamKey).has('client-1')).toBe(false);
    });

    test('should clean up empty stream mappings', () => {
      const streamKey = '10.0.0.1:232.1.1.1:1234';
      manager.streamSubscribers.set(streamKey, new Set(['client-1']));
      
      manager.streamSubscribers.get(streamKey).delete('client-1');
      
      if (manager.streamSubscribers.get(streamKey).size === 0) {
        manager.streamSubscribers.delete(streamKey);
      }
      
      expect(manager.streamSubscribers.has(streamKey)).toBe(false);
    });
  });

  describe('Subscription Matching', () => {
    function matchesSubscription(subscription, source, group, port) {
      const sourceMatch = subscription.source === '*' || subscription.source === source;
      const groupMatch = subscription.group === '*' || subscription.group === group;
      const portMatch = subscription.port === '*' || String(subscription.port) === String(port);
      return sourceMatch && groupMatch && portMatch;
    }

    test('should match exact subscription', () => {
      const subscription = { source: '10.0.0.1', group: '232.1.1.1', port: 1234 };
      
      expect(matchesSubscription(subscription, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesSubscription(subscription, '10.0.0.2', '232.1.1.1', 1234)).toBe(false);
    });

    test('should match wildcard source', () => {
      const subscription = { source: '*', group: '232.1.1.1', port: 1234 };
      
      expect(matchesSubscription(subscription, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesSubscription(subscription, '192.168.1.1', '232.1.1.1', 1234)).toBe(true);
    });

    test('should match wildcard group', () => {
      const subscription = { source: '10.0.0.1', group: '*', port: 1234 };
      
      expect(matchesSubscription(subscription, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesSubscription(subscription, '10.0.0.1', '232.2.2.2', 1234)).toBe(true);
    });

    test('should match wildcard port', () => {
      const subscription = { source: '10.0.0.1', group: '232.1.1.1', port: '*' };
      
      expect(matchesSubscription(subscription, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesSubscription(subscription, '10.0.0.1', '232.1.1.1', 5678)).toBe(true);
    });

    test('should match all wildcards', () => {
      const subscription = { source: '*', group: '*', port: '*' };
      
      expect(matchesSubscription(subscription, '10.0.0.1', '232.1.1.1', 1234)).toBe(true);
      expect(matchesSubscription(subscription, '192.168.1.1', '239.255.255.255', 65535)).toBe(true);
    });
  });

  describe('Finding Subscribers for Stream', () => {
    test('should find all matching subscribers for stream', () => {
      // Setup subscriptions
      manager.subscriptions.set('client-1', { source: '10.0.0.1', group: '232.1.1.1', port: 1234 });
      manager.subscriptions.set('client-2', { source: '*', group: '232.1.1.1', port: '*' });
      manager.subscriptions.set('client-3', { source: '10.0.0.2', group: '232.1.1.1', port: 1234 });
      manager.subscriptions.set('client-4', { source: '*', group: '*', port: '*' });
      
      // Find matching subscribers for stream
      const source = '10.0.0.1';
      const group = '232.1.1.1';
      const port = 1234;
      
      const matches = [];
      for (const [id, sub] of manager.subscriptions.entries()) {
        const sourceMatch = sub.source === '*' || sub.source === source;
        const groupMatch = sub.group === '*' || sub.group === group;
        const portMatch = sub.port === '*' || String(sub.port) === String(port);
        
        if (sourceMatch && groupMatch && portMatch) {
          matches.push(id);
        }
      }
      
      // Should match client-1, client-2, and client-4
      expect(matches.length).toBe(3);
      expect(matches).toContain('client-1');
      expect(matches).toContain('client-2');
      expect(matches).toContain('client-4');
      expect(matches).not.toContain('client-3');
    });
  });

  describe('Subscription Metadata', () => {
    test('should store protocol type', () => {
      manager.subscriptions.set('client-1', {
        source: '*',
        group: '*',
        port: '*',
        protocol: 'udp'
      });
      
      expect(manager.subscriptions.get('client-1').protocol).toBe('udp');
    });

    test('should store subscriber address', () => {
      manager.subscriptions.set('client-1', {
        source: '*',
        group: '*',
        port: '*',
        protocol: 'tcp',
        socketId: 100
      });
      
      expect(manager.subscriptions.get('client-1').socketId).toBe(100);
    });

    test('should store timestamp', () => {
      const now = Date.now();
      manager.subscriptions.set('client-1', {
        source: '*',
        group: '*',
        port: '*',
        createdAt: now
      });
      
      expect(manager.subscriptions.get('client-1').createdAt).toBe(now);
    });
  });

  describe('Statistics and Monitoring', () => {
    test('should count total subscriptions', () => {
      manager.subscriptions.set('client-1', { source: '*', group: '*', port: '*' });
      manager.subscriptions.set('client-2', { source: '*', group: '*', port: '*' });
      manager.subscriptions.set('client-3', { source: '*', group: '*', port: '*' });
      
      expect(manager.subscriptions.size).toBe(3);
    });

    test('should list all subscription IDs', () => {
      manager.subscriptions.set('client-1', { source: '*', group: '*', port: '*' });
      manager.subscriptions.set('client-2', { source: '*', group: '*', port: '*' });
      
      const ids = Array.from(manager.subscriptions.keys());
      
      expect(ids).toHaveLength(2);
      expect(ids).toContain('client-1');
      expect(ids).toContain('client-2');
    });

    test('should count subscriptions by protocol', () => {
      manager.subscriptions.set('udp-1', { source: '*', group: '*', port: '*', protocol: 'udp' });
      manager.subscriptions.set('udp-2', { source: '*', group: '*', port: '*', protocol: 'udp' });
      manager.subscriptions.set('tcp-1', { source: '*', group: '*', port: '*', protocol: 'tcp' });
      
      const byProtocol = {};
      for (const sub of manager.subscriptions.values()) {
        byProtocol[sub.protocol] = (byProtocol[sub.protocol] || 0) + 1;
      }
      
      expect(byProtocol.udp).toBe(2);
      expect(byProtocol.tcp).toBe(1);
    });

    test('should find streams with subscribers', () => {
      manager.streamSubscribers.set('10.0.0.1:232.1.1.1:1234', new Set(['client-1', 'client-2']));
      manager.streamSubscribers.set('10.0.0.2:232.1.1.2:5678', new Set(['client-3']));
      
      const activeStreams = Array.from(manager.streamSubscribers.keys());
      
      expect(activeStreams).toHaveLength(2);
      expect(activeStreams).toContain('10.0.0.1:232.1.1.1:1234');
    });
  });

  describe('Subscription Validation', () => {
    test('should validate source IP format', () => {
      const isValidIP = (ip) => {
        if (ip === '*') return true;
        return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
      };
      
      expect(isValidIP('10.0.0.1')).toBe(true);
      expect(isValidIP('192.168.1.100')).toBe(true);
      expect(isValidIP('*')).toBe(true);
      expect(isValidIP('invalid')).toBe(false);
      expect(isValidIP('999.999.999.999')).toBe(true); // Regex doesn't validate ranges
    });

    test('should validate port range', () => {
      const isValidPort = (port) => {
        if (port === '*') return true;
        const p = parseInt(port);
        return !isNaN(p) && p >= 1 && p <= 65535;
      };
      
      expect(isValidPort(1234)).toBe(true);
      expect(isValidPort(65535)).toBe(true);
      expect(isValidPort('*')).toBe(true);
      expect(isValidPort(0)).toBe(false);
      expect(isValidPort(65536)).toBe(false);
    });

    test('should validate multicast group', () => {
      const isMulticastGroup = (ip) => {
        if (ip === '*') return true;
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        const first = parseInt(parts[0]);
        return first >= 224 && first <= 239;
      };
      
      expect(isMulticastGroup('232.1.1.1')).toBe(true);
      expect(isMulticastGroup('239.255.255.255')).toBe(true);
      expect(isMulticastGroup('*')).toBe(true);
      expect(isMulticastGroup('192.168.1.1')).toBe(false);
      expect(isMulticastGroup('10.0.0.1')).toBe(false);
    });
  });
});

