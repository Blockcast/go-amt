/**
 * Server Manager
 * 
 * Coordinates all output servers (UDP, TCP, WebSocket, WebRTC) and provides:
 * - Unified lifecycle management (start/stop all servers)
 * - Packet distribution to all active servers
 * - Health monitoring and statistics
 * - Graceful shutdown handling
 * 
 * This is the main entry point for managing all output server infrastructure.
 */

export class ServerManager {
  constructor() {
    // Map: serverName -> server instance
    this.servers = new Map();
    
    // Manager state
    this.enabled = false;
    this.startTime = null;
    
    // Statistics
    this.stats = {
      totalPackets: 0,
      totalBytes: 0,
      startedAt: null,
      errors: []
    };
  }

  /**
   * Register an output server
   * 
   * @param {string} name - Server name (e.g., 'udp', 'tcp', 'websocket')
   * @param {Object} server - Server instance with start/stop/broadcastPacket methods
   * @returns {boolean} Success
   */
  registerServer(name, server) {
    try {
      if (!name || !server) {
        throw new Error('Invalid server registration');
      }

      if (this.servers.has(name)) {
        console.warn(`[ServerManager] Server '${name}' already registered, replacing`);
      }

      this.servers.set(name, server);
      console.log(`[ServerManager] ✓ Registered server: ${name}`);

      return true;
    } catch (error) {
      console.error(`[ServerManager] Failed to register server '${name}':`, error);
      return false;
    }
  }

  /**
   * Unregister an output server
   * 
   * @param {string} name - Server name
   * @returns {Promise<boolean>} Success
   */
  async unregisterServer(name) {
    try {
      if (!this.servers.has(name)) {
        return false;
      }

      // Stop server if running
      const server = this.servers.get(name);
      if (server.enabled) {
        await server.stop();
      }

      this.servers.delete(name);
      console.log(`[ServerManager] ✓ Unregistered server: ${name}`);

      return true;
    } catch (error) {
      console.error(`[ServerManager] Failed to unregister server '${name}':`, error);
      return false;
    }
  }

  /**
   * Start all registered servers
   * 
   * @returns {Promise<Object>} Start results by server name
   */
  async startAll() {
    console.log('[ServerManager] Starting all servers...');

    const results = {};
    const promises = [];

    for (const [name, server] of this.servers.entries()) {
      promises.push(
        server.start()
          .then(() => {
            results[name] = { success: true };
            console.log(`[ServerManager] ✓ ${name} server started`);
          })
          .catch((error) => {
            results[name] = { success: false, error: error.message };
            console.error(`[ServerManager] ✗ ${name} server failed to start:`, error);
            this.stats.errors.push({ server: name, error: error.message, timestamp: Date.now() });
          })
      );
    }

    await Promise.allSettled(promises);

    this.enabled = true;
    this.startTime = Date.now();
    this.stats.startedAt = this.startTime;

    const successCount = Object.values(results).filter(r => r.success).length;
    console.log(`[ServerManager] ✓ Started ${successCount}/${this.servers.size} servers`);

    return results;
  }

  /**
   * Stop all registered servers
   * 
   * Stops servers in reverse order for graceful shutdown.
   * 
   * @returns {Promise<Object>} Stop results by server name
   */
  async stopAll() {
    console.log('[ServerManager] Stopping all servers...');

    const results = {};
    const serverArray = Array.from(this.servers.entries()).reverse();

    // Stop in reverse order (last started = first stopped)
    for (const [name, server] of serverArray) {
      try {
        await server.stop();
        results[name] = { success: true };
        console.log(`[ServerManager] ✓ ${name} server stopped`);
      } catch (error) {
        results[name] = { success: false, error: error.message };
        console.error(`[ServerManager] ✗ ${name} server failed to stop:`, error);
        this.stats.errors.push({ server: name, error: error.message, timestamp: Date.now() });
      }
    }

    this.enabled = false;

    console.log('[ServerManager] ✓ All servers stopped');

    return results;
  }

  /**
   * Handle incoming packet and forward to all output servers
   * 
   * @param {Uint8Array} packet - Raw packet data
   * @param {string} sourceIP - Source IP address
   * @param {string} groupIP - Multicast group IP
   * @param {number} port - Port number
   * @returns {Promise<number>} Total count of clients that received the packet
   */
  async handleIncomingPacket(packet, sourceIP, groupIP, port) {
    let totalSent = 0;

    for (const [name, server] of this.servers.entries()) {
      // Skip disabled servers
      if (!server.enabled) {
        continue;
      }

      try {
        const count = await server.broadcastPacket(packet, sourceIP, groupIP, port);
        totalSent += count || 0;
      } catch (error) {
        console.error(`[ServerManager] Failed to forward packet to ${name}:`, error);
      }
    }

    // Update stats
    this.stats.totalPackets++;
    this.stats.totalBytes += packet.length;

    return totalSent;
  }

  /**
   * Broadcast packet to all enabled servers
   * 
   * @param {Uint8Array} packet - Raw packet data
   * @param {string} sourceIP - Source IP address
   * @param {string} groupIP - Multicast group IP
   * @param {number} port - Port number
   * @returns {Promise<Object>} Broadcast results by server name
   */
  async broadcastToAll(packet, sourceIP, groupIP, port) {
    const results = {};
    const promises = [];

    for (const [name, server] of this.servers.entries()) {
      // Skip disabled servers
      if (!server.enabled) {
        results[name] = { skipped: true, reason: 'disabled' };
        continue;
      }

      promises.push(
        server.broadcastPacket(packet, sourceIP, groupIP, port)
          .then((count) => {
            results[name] = { success: true, clientCount: count };
          })
          .catch((error) => {
            results[name] = { success: false, error: error.message };
            console.error(`[ServerManager] Broadcast to ${name} failed:`, error);
          })
      );
    }

    await Promise.allSettled(promises);

    // Update stats
    this.stats.totalPackets++;
    this.stats.totalBytes += packet.length;

    return results;
  }

  /**
   * Get server by name
   * 
   * @param {string} name - Server name
   * @returns {Object|null} Server instance or null
   */
  getServer(name) {
    return this.servers.get(name) || null;
  }

  /**
   * Get all server names
   * 
   * @returns {Array<string>} Server names
   */
  getServerNames() {
    return Array.from(this.servers.keys());
  }

  /**
   * Get count of registered servers
   * 
   * @returns {number} Server count
   */
  getServerCount() {
    return this.servers.size;
  }

  /**
   * Get count of enabled servers
   * 
   * @returns {number} Enabled server count
   */
  getEnabledServerCount() {
    return Array.from(this.servers.values())
      .filter(s => s.enabled).length;
  }

  /**
   * Check if all servers are healthy
   * 
   * @returns {Object} Health status by server name
   */
  checkHealth() {
    const health = {};

    for (const [name, server] of this.servers.entries()) {
      health[name] = {
        enabled: server.enabled,
        healthy: server.isHealthy ? server.isHealthy() : true,
        lastError: server.lastError || null
      };
    }

    return health;
  }

  /**
   * Get status of all servers
   * 
   * @returns {Object} Combined status object
   */
  getStatus() {
    const status = {
      manager: {
        enabled: this.enabled,
        serverCount: this.servers.size,
        enabledCount: this.getEnabledServerCount(),
        uptime: this.startTime ? Date.now() - this.startTime : 0
      },
      servers: {},
      health: this.checkHealth(),
      stats: this.getStats()
    };

    // Get status from each server
    for (const [name, server] of this.servers.entries()) {
      status.servers[name] = server.getStatus ? server.getStatus() : { enabled: server.enabled };
    }

    return status;
  }

  /**
   * Get aggregated statistics
   * 
   * @returns {Object} Statistics object
   */
  getStats() {
    const aggregated = {
      ...this.stats,
      uptime: this.startTime ? Date.now() - this.startTime : 0,
      servers: {}
    };

    // Aggregate stats from each server
    for (const [name, server] of this.servers.entries()) {
      if (server.getStats) {
        aggregated.servers[name] = server.getStats();
      }
    }

    // Calculate totals
    aggregated.totalSubscribers = 0;
    aggregated.totalServerPackets = 0;

    for (const serverStats of Object.values(aggregated.servers)) {
      aggregated.totalSubscribers += (serverStats.subscriptions || serverStats.clients || 0);
      aggregated.totalServerPackets += (serverStats.packetsSent || 0);
    }

    return aggregated;
  }

  /**
   * Reset statistics
   */
  resetStats() {
    this.stats = {
      totalPackets: 0,
      totalBytes: 0,
      startedAt: this.startTime,
      errors: []
    };

    console.log('[ServerManager] ✓ Statistics reset');
  }

  /**
   * Graceful shutdown
   * 
   * Stops all servers and cleans up resources.
   * 
   * @returns {Promise<boolean>} Success
   */
  async shutdown() {
    console.log('[ServerManager] Initiating graceful shutdown...');

    try {
      // Stop all servers
      await this.stopAll();

      // Clear server registry
      this.servers.clear();

      // Reset state
      this.enabled = false;
      this.startTime = null;

      console.log('[ServerManager] ✓ Shutdown complete');

      return true;
    } catch (error) {
      console.error('[ServerManager] Shutdown error:', error);
      return false;
    }
  }
}

// Export singleton instance
export const serverManager = new ServerManager();

