// udp-server.js
// UDP Output Server using Direct Sockets API
// Implements protocol-agnostic multicast forwarding via UDP

import { DEFAULT_CONFIG, MSG_TYPE, WILDCARD } from '../constants.js';

export class LocalUDPServer {
  constructor() {
    this.controlSocket = null;     // UDPSocket for subscription control
    this.dataSocket = null;         // UDPSocket for sending packets
    this.subscriptions = new Map(); // clientKey → [subscription filters]
    this.enabled = false;
    this.controlPort = DEFAULT_CONFIG.UDP_CONTROL_PORT;
    this.dataPort = 0; // Ephemeral
  }
  
  /**
   * Start UDP server using Direct Sockets API
   */
  async start(controlPort = DEFAULT_CONFIG.UDP_CONTROL_PORT) {
    const bindAddress = '127.0.0.1';
    console.log(`[UDP Server] Starting on ${bindAddress}:${controlPort}...`);
    
    try {
      // Create control socket for subscriptions (Direct Sockets API)
      // MUST provide BOTH localAddress AND localPort (Chrome requires both or neither)
      this.controlSocket = new UDPSocket({
        localAddress: bindAddress,
        localPort: controlPort
      });
      
      // Wait for socket to open
      const controlInfo = await this.controlSocket.opened;
      console.log(`[UDP Server] ✓ Control socket: ${controlInfo.localAddress}:${controlInfo.localPort}`);
      
      // For data socket: Use writable stream from control socket for sending
      // Chrome's Direct Sockets API for UDP doesn't support separate send-only sockets
      // We'll use the control socket's writable stream for sending data packets
      const controlWritable = controlInfo.writable;
      this.dataWriter = controlWritable.getWriter();
      this.dataPort = controlInfo.localPort;  // Same as control port for now
      console.log(`[UDP Server] ✓ Data socket: Using control socket for sending (${controlInfo.localAddress}:${controlInfo.localPort})`);
      
      // Start receiving control messages
      this.startReceiving();
      
      this.enabled = true;
      console.log('[UDP Server] ✓ Started');
      
      return true;
    } catch (error) {
      console.error('[UDP Server] Failed to start:', error);
      throw error;
    }
  }
  
  /**
   * Stop UDP server
   */
  async stop() {
    if (!this.enabled) return;
    
    console.log('[UDP Server] Stopping...');
    
    if (this.dataWriter) {
      try {
        await this.dataWriter.close();
      } catch (e) {
        // Ignore close errors
      }
      this.dataWriter = null;
    }
    
    if (this.controlSocket) {
      await this.controlSocket.close();
      this.controlSocket = null;
    }
    
    this.subscriptions.clear();
    this.enabled = false;
    
    console.log('[UDP Server] ✓ Stopped');
  }
  
  /**
   * Start receiving control messages
   */
  async startReceiving() {
    const { readable } = await this.controlSocket.opened;
    const reader = readable.getReader();
    
    try {
      while (this.enabled) {
        const { value, done } = await reader.read();
        
        if (done) {
          console.log('[UDP Server] Control socket closed');
          break;
        }
        
        const { data, remoteAddress, remotePort } = value;
        this.handleControlMessage(data, remoteAddress, remotePort);
      }
    } catch (error) {
      if (this.enabled) {
        console.error('[UDP Server] Reception error:', error);
      }
    } finally {
      reader.releaseLock();
    }
  }
  
  /**
   * Handle subscription control messages
   */
  handleControlMessage(data, remoteAddress, remotePort) {
    try {
      const msg = JSON.parse(new TextDecoder().decode(data));
      const clientKey = `${remoteAddress}:${remotePort}`;
      
      if (msg.type === MSG_TYPE.SUBSCRIBE) {
        this.addSubscription(clientKey, msg, remoteAddress, remotePort);
      } else if (msg.type === MSG_TYPE.UNSUBSCRIBE) {
        this.removeSubscription(clientKey, msg);
      }
    } catch (error) {
      console.error('[UDP Server] Failed to parse control message:', error);
    }
  }
  
  /**
   * Add client subscription
   */
  async addSubscription(clientKey, msg, clientAddress, clientPort) {
    const filters = this.subscriptions.get(clientKey) || [];
    
    const subscription = {
      source: msg.source || WILDCARD.SOURCE,
      group: msg.group,
      port: msg.port,
      clientAddress,
      clientPort: msg.clientPort || clientPort
    };
    
    filters.push(subscription);
    this.subscriptions.set(clientKey, filters);
    
    console.log(`[UDP Server] ✓ ${clientKey} subscribed to ${subscription.source}@${subscription.group}:${subscription.port}`);
    
    // Send ACK
    const ack = JSON.stringify({ 
      type: MSG_TYPE.ACK, 
      subscribed: {
        source: subscription.source,
        group: subscription.group,
        port: subscription.port
      },
      dataPort: this.dataPort
    });
    
    await this.sendControl(new TextEncoder().encode(ack), clientAddress, clientPort);
  }
  
  /**
   * Remove client subscription
   */
  removeSubscription(clientKey, msg) {
    const filters = this.subscriptions.get(clientKey) || [];
    const updated = filters.filter(f => 
      !(f.source === msg.source && f.group === msg.group)
    );
    
    if (updated.length > 0) {
      this.subscriptions.set(clientKey, updated);
    } else {
      this.subscriptions.delete(clientKey);
    }
    
    console.log(`[UDP Server] ✓ ${clientKey} unsubscribed from ${msg.source}@${msg.group}`);
  }
  
  /**
   * Broadcast packet to subscribed clients
   */
  async broadcastPacket(rawPayload, sourceIP, groupIP, groupPort) {
    if (!this.enabled || !this.dataSocket) {
      return 0;
    }
    
    let sentCount = 0;
    
    // Send to all matching subscriptions
    for (const [clientKey, filters] of this.subscriptions) {
      for (const filter of filters) {
        if (this.matchesFilter(filter, sourceIP, groupIP, groupPort)) {
          await this.sendData(
            rawPayload,
            filter.clientAddress,
            filter.clientPort
          );
          sentCount++;
        }
      }
    }
    
    return sentCount;
  }
  
  /**
   * Check if packet matches subscription filter
   */
  matchesFilter(filter, sourceIP, groupIP, groupPort) {
    const sourceMatch = filter.source === WILDCARD.SOURCE || filter.source === sourceIP;
    const groupMatch = filter.group === WILDCARD.GROUP || filter.group === groupIP;
    const portMatch = !filter.port || filter.port === WILDCARD.PORT || filter.port == groupPort;
    return sourceMatch && groupMatch && portMatch;
  }
  
  /**
   * Send control message
   */
  async sendControl(data, address, port) {
    if (!this.controlSocket) return;
    
    try {
      const { writable } = await this.controlSocket.opened;
      const writer = writable.getWriter();
      
      await writer.write({
        data: data,
        remoteAddress: address,
        remotePort: port
      });
      
      writer.releaseLock();
    } catch (error) {
      console.error('[UDP Server] Failed to send control message:', error);
    }
  }
  
  /**
   * Send data packet
   */
  async sendData(data, address, port) {
    if (!this.dataWriter) return;
    
    try {
      // Ensure data is ArrayBuffer
      const buffer = data instanceof ArrayBuffer ? data : 
                     data.buffer ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) :
                     new Uint8Array(data).buffer;
      
      await this.dataWriter.write({
        data: buffer,
        remoteAddress: address,
        remotePort: port
      });
    } catch (error) {
      console.error(`[UDP Server] Failed to send data to ${address}:${port}:`, error);
    }
  }
  
  /**
   * Get server status
   */
  getStatus() {
    return {
      enabled: this.enabled,
      controlPort: this.controlPort,
      dataPort: this.dataPort,
      subscriptions: this.subscriptions.size
    };
  }
}

// Export singleton instance
export const udpServer = new LocalUDPServer();



