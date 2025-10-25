/**
 * Subscription Manager
 * 
 * Central component that tracks all subscriptions across all output servers
 * and manages stream-to-subscriber mapping.
 * 
 * This enables:
 * - Efficient packet distribution (one-to-many)
 * - Subscription lifecycle management
 * - Cross-server coordination
 * - Statistics and monitoring
 */

import { WILDCARD } from '../constants.js';

export class SubscriptionManager {
  constructor() {
    // Map: subscriberId -> subscription object
    this.subscriptions = new Map();
    
    // Map: streamKey (source:group:port) -> Set<subscriberId>
    // This reverse index allows fast lookup of who wants a stream
    this.streamSubscribers = new Map();
    
    // Statistics
    this.stats = {
      totalSubscriptions: 0,
      totalStreams: 0,
      subscriptionsByProtocol: {},
      lastUpdated: Date.now()
    };
  }

  /**
   * Add a new subscription
   * 
   * @param {string} subscriberId - Unique identifier for subscriber
   * @param {Object} subscription - Subscription details
   * @param {string} subscription.source - Source IP or wildcard (*)
   * @param {string} subscription.group - Multicast group IP or wildcard (*)
   * @param {number|string} subscription.port - Port number or wildcard (*)
   * @param {string} subscription.protocol - 'udp', 'tcp', 'websocket', etc.
   * @param {Object} subscription.metadata - Protocol-specific metadata (socket ID, address, etc.)
   * @returns {boolean} Success
   */
  addSubscription(subscriberId, subscription) {
    try {
      // Validate subscription
      if (!this.validateSubscription(subscription)) {
        console.error('[SubscriptionManager] Invalid subscription:', subscription);
        return false;
      }

      // Store subscription
      const sub = {
        ...subscription,
        id: subscriberId,
        createdAt: Date.now(),
        lastActivity: Date.now()
      };

      // Remove old subscription if exists
      if (this.subscriptions.has(subscriberId)) {
        this.removeSubscription(subscriberId);
      }

      this.subscriptions.set(subscriberId, sub);

      // Update reverse index for efficient stream matching
      this.updateStreamIndex(subscriberId, sub);

      // Update stats
      this.updateStats();

      console.log(`[SubscriptionManager] ✓ Added subscription: ${subscriberId} (${sub.protocol})`);
      console.log(`  Filter: ${sub.source}:${sub.group}:${sub.port}`);

      return true;
    } catch (error) {
      console.error('[SubscriptionManager] Error adding subscription:', error);
      return false;
    }
  }

  /**
   * Remove a subscription
   * 
   * @param {string} subscriberId - Subscriber to remove
   * @returns {boolean} Success
   */
  removeSubscription(subscriberId) {
    try {
      const subscription = this.subscriptions.get(subscriberId);
      if (!subscription) {
        return false;
      }

      // Remove from all stream mappings
      for (const [streamKey, subscribers] of this.streamSubscribers.entries()) {
        subscribers.delete(subscriberId);
        
        // Clean up empty sets
        if (subscribers.size === 0) {
          this.streamSubscribers.delete(streamKey);
        }
      }

      // Remove subscription
      this.subscriptions.delete(subscriberId);

      // Update stats
      this.updateStats();

      console.log(`[SubscriptionManager] ✓ Removed subscription: ${subscriberId}`);

      return true;
    } catch (error) {
      console.error('[SubscriptionManager] Error removing subscription:', error);
      return false;
    }
  }

  /**
   * Get all subscribers for a specific stream
   * 
   * @param {string} source - Source IP address
   * @param {string} group - Multicast group IP
   * @param {number} port - Port number
   * @returns {Array<Object>} Array of matching subscriptions with subscriber info
   */
  getSubscribersForStream(source, group, port) {
    const matches = [];

    for (const [id, subscription] of this.subscriptions.entries()) {
      if (this.matchesFilter(subscription, source, group, port)) {
        matches.push({
          id,
          ...subscription
        });
      }
    }

    return matches;
  }

  /**
   * Check if a subscription matches a stream
   * 
   * @param {Object} subscription - Subscription filter
   * @param {string} source - Source IP
   * @param {string} group - Group IP
   * @param {number} port - Port
   * @returns {boolean} Match result
   */
  matchesFilter(subscription, source, group, port) {
    const sourceMatch = 
      subscription.source === WILDCARD.SOURCE || 
      subscription.source === source;

    const groupMatch = 
      subscription.group === WILDCARD.GROUP || 
      subscription.group === group;

    const portMatch = 
      subscription.port === WILDCARD.PORT || 
      String(subscription.port) === String(port);

    return sourceMatch && groupMatch && portMatch;
  }

  /**
   * Update stream-to-subscriber reverse index
   * 
   * This index allows O(1) lookup of subscribers for exact stream matches,
   * avoiding the need to scan all subscriptions on every packet.
   * 
   * @param {string} subscriberId - Subscriber ID
   * @param {Object} subscription - Subscription object
   */
  updateStreamIndex(subscriberId, subscription) {
    // For exact matches (no wildcards), create direct mapping
    if (subscription.source !== WILDCARD.SOURCE &&
        subscription.group !== WILDCARD.GROUP &&
        subscription.port !== WILDCARD.PORT) {
      
      const streamKey = this.getStreamKey(
        subscription.source,
        subscription.group,
        subscription.port
      );

      if (!this.streamSubscribers.has(streamKey)) {
        this.streamSubscribers.set(streamKey, new Set());
      }

      this.streamSubscribers.get(streamKey).add(subscriberId);
    }
    
    // Note: Wildcard subscriptions require full scan and aren't indexed
  }

  /**
   * Create stream key from source/group/port
   * 
   * @param {string} source - Source IP
   * @param {string} group - Group IP
   * @param {number} port - Port
   * @returns {string} Stream key
   */
  getStreamKey(source, group, port) {
    return `${source}:${group}:${port}`;
  }

  /**
   * Validate subscription parameters
   * 
   * @param {Object} subscription - Subscription to validate
   * @returns {boolean} Valid
   */
  validateSubscription(subscription) {
    if (!subscription) return false;

    // Validate source
    if (!subscription.source || 
        (subscription.source !== WILDCARD.SOURCE && !this.isValidIP(subscription.source))) {
      return false;
    }

    // Validate group  
    if (!subscription.group ||
        (subscription.group !== WILDCARD.GROUP && !this.isValidMulticastIP(subscription.group))) {
      return false;
    }

    // Validate port
    if (subscription.port !== WILDCARD.PORT && !this.isValidPort(subscription.port)) {
      return false;
    }

    // Validate protocol
    if (!subscription.protocol) {
      return false;
    }

    return true;
  }

  /**
   * Validate IP address format
   * 
   * @param {string} ip - IP address
   * @returns {boolean} Valid
   */
  isValidIP(ip) {
    if (ip === WILDCARD.SOURCE) return true;
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip);
  }

  /**
   * Validate multicast IP address
   * 
   * @param {string} ip - IP address
   * @returns {boolean} Valid multicast
   */
  isValidMulticastIP(ip) {
    if (ip === WILDCARD.GROUP) return true;
    
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    
    const first = parseInt(parts[0]);
    return first >= 224 && first <= 239;
  }

  /**
   * Validate port number
   * 
   * @param {number|string} port - Port number
   * @returns {boolean} Valid
   */
  isValidPort(port) {
    if (port === WILDCARD.PORT) return true;
    
    const p = parseInt(port);
    return !isNaN(p) && p >= 1 && p <= 65535;
  }

  /**
   * Update activity timestamp for subscriber
   * 
   * @param {string} subscriberId - Subscriber ID
   */
  updateActivity(subscriberId) {
    const subscription = this.subscriptions.get(subscriberId);
    if (subscription) {
      subscription.lastActivity = Date.now();
    }
  }

  /**
   * Get subscription by ID
   * 
   * @param {string} subscriberId - Subscriber ID
   * @returns {Object|null} Subscription or null
   */
  getSubscription(subscriberId) {
    return this.subscriptions.get(subscriberId) || null;
  }

  /**
   * Get all subscriptions
   * 
   * @returns {Array<Object>} All subscriptions
   */
  getAllSubscriptions() {
    return Array.from(this.subscriptions.values());
  }

  /**
   * Get subscriptions by protocol
   * 
   * @param {string} protocol - Protocol name
   * @returns {Array<Object>} Subscriptions for protocol
   */
  getSubscriptionsByProtocol(protocol) {
    return Array.from(this.subscriptions.values())
      .filter(sub => sub.protocol === protocol);
  }

  /**
   * Update statistics
   */
  updateStats() {
    this.stats.totalSubscriptions = this.subscriptions.size;
    this.stats.totalStreams = this.streamSubscribers.size;
    this.stats.lastUpdated = Date.now();

    // Count by protocol
    this.stats.subscriptionsByProtocol = {};
    for (const subscription of this.subscriptions.values()) {
      const proto = subscription.protocol;
      this.stats.subscriptionsByProtocol[proto] = 
        (this.stats.subscriptionsByProtocol[proto] || 0) + 1;
    }
  }

  /**
   * Get statistics
   * 
   * @returns {Object} Statistics object
   */
  getStats() {
    this.updateStats();
    return { ...this.stats };
  }

  /**
   * Get status for monitoring
   * 
   * @returns {Object} Status object
   */
  getStatus() {
    return {
      subscriptions: this.subscriptions.size,
      streams: this.streamSubscribers.size,
      protocols: this.stats.subscriptionsByProtocol,
      ...this.stats
    };
  }

  /**
   * Clear all subscriptions
   */
  clear() {
    this.subscriptions.clear();
    this.streamSubscribers.clear();
    this.updateStats();
    console.log('[SubscriptionManager] ✓ Cleared all subscriptions');
  }
}

// Export singleton instance
export const subscriptionManager = new SubscriptionManager();




