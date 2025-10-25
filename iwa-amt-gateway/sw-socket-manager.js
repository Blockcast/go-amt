// sw-socket-manager.js
// Clean UDP socket management for Service Worker
// Supports multiple sockets (one per relay)
'use strict';

class SocketManager {
  constructor() {
    // Map of relay sockets: relayId -> { socket, readable, writable, writer, reader, isReceiving, localAddress, localPort }
    this.sockets = new Map();
    this.packetCount = 0;
  }

  /**
   * Create a UDP socket for a specific relay
   * @param {string} relayId - Unique identifier for the relay (e.g., "relay-162.250.137.254-2268")
   * @returns {Promise<{localAddress: string, localPort: number, relayId: string}>}
   */
  async createSocket(relayId = 'default') {
    // Check if socket already exists for this relay
    if (this.sockets.has(relayId)) {
      const existing = this.sockets.get(relayId);
      console.log(`[SocketManager] Socket already exists for relay ${relayId} at ${existing.localAddress}:${existing.localPort}`);
      return {
        localAddress: existing.localAddress,
        localPort: existing.localPort,
        relayId
      };
    }

    console.log(`[SocketManager] Creating UDP socket for relay ${relayId}...`);
    
    // Create socket - let OS assign port automatically
    const socket = new UDPSocket({
      localAddress: '0.0.0.0'
    });
    
    // Wait for socket to be ready
    const info = await socket.opened;
    
    const localAddress = info.localAddress || '0.0.0.0';
    const localPort = info.localPort || 0;
    
    // Store socket info
    this.sockets.set(relayId, {
      socket,
      readable: info.readable,
      writable: info.writable,
      writer: null,
      reader: null,
      isReceiving: false,
      localAddress,
      localPort
    });
    
    console.log(`[SocketManager] ✓ Socket created for relay ${relayId} at ${localAddress}:${localPort}`);
    
    return { localAddress, localPort, relayId };
  }

  /**
   * Send UDP packet to a remote address
   * @param {ArrayBuffer} buffer - Data to send
   * @param {string} remoteAddress - Destination IP
   * @param {number} remotePort - Destination port
   * @param {string} relayId - Relay identifier
   */
  async sendUDP(buffer, remoteAddress, remotePort, relayId = 'default') {
    const socketInfo = this.sockets.get(relayId);
    
    if (!socketInfo || !socketInfo.writable) {
      throw new Error(`Socket not available for relay ${relayId}`);
    }
    
    // Get writer once and reuse it
    if (!socketInfo.writer) {
      socketInfo.writer = socketInfo.writable.getWriter();
    }
    
    await socketInfo.writer.write({
      data: buffer,
      remoteAddress,
      remotePort
    });
    
    console.log(`[SocketManager] Sent ${buffer.byteLength} bytes to ${remoteAddress}:${remotePort} via relay ${relayId}`);
  }

  /**
   * Start receiving packets for a relay
   * @param {string} relayId - Relay identifier
   * @param {Function} onPacket - Callback for received packets: (packet, remoteAddress, remotePort, relayId) => void
   */
  async startReceiving(relayId = 'default', onPacket) {
    const socketInfo = this.sockets.get(relayId);
    
    if (!socketInfo) {
      throw new Error(`No socket found for relay ${relayId}`);
    }
    
    if (socketInfo.isReceiving) {
      console.log(`[SocketManager] Already receiving for relay ${relayId}`);
      return;
    }
    
    if (!socketInfo.readable) {
      throw new Error(`Readable stream not available for relay ${relayId}`);
    }
    
    socketInfo.isReceiving = true;
    console.log(`[SocketManager] Starting packet reception for relay ${relayId}...`);
    
    // Get reader once and reuse it
    if (!socketInfo.reader) {
      socketInfo.reader = socketInfo.readable.getReader();
    }
    
    const reader = socketInfo.reader;
    
    // Start reading loop
    this._receiveLoop(relayId, reader, onPacket);
  }

  /**
   * Internal receive loop
   */
  async _receiveLoop(relayId, reader, onPacket) {
    const socketInfo = this.sockets.get(relayId);
    
    try {
      while (socketInfo && socketInfo.isReceiving) {
        const { value, done } = await reader.read();
        
        if (done) {
          console.log(`[SocketManager] Socket closed for relay ${relayId}`);
          break;
        }
        
        const { data, remoteAddress, remotePort } = value;
        this.packetCount++;
        
        if (this.packetCount % 1000 === 0) {
          console.log(`[SocketManager] Relay ${relayId} packet #${this.packetCount}: ${data.byteLength} bytes from ${remoteAddress}:${remotePort}`);
        }
        
        // Convert ArrayBuffer to Uint8Array
        const packet = new Uint8Array(data);
        
        // Invoke callback
        if (onPacket) {
          onPacket(packet, remoteAddress, remotePort, relayId);
        }
      }
    } catch (error) {
      console.error(`[SocketManager] Reception error for relay ${relayId}:`, error);
      if (socketInfo) {
        socketInfo.isReceiving = false;
      }
    }
  }

  /**
   * Stop receiving packets for a relay
   * @param {string} relayId - Relay identifier
   */
  async stopReceiving(relayId = 'default') {
    const socketInfo = this.sockets.get(relayId);
    
    if (!socketInfo) {
      console.warn(`[SocketManager] No socket found for relay ${relayId}`);
      return;
    }
    
    if (socketInfo.isReceiving) {
      socketInfo.isReceiving = false;
      console.log(`[SocketManager] Stopping packet reception for relay ${relayId}...`);
      
      // Release reader
      if (socketInfo.reader) {
        try {
          await socketInfo.reader.cancel();
          socketInfo.reader = null;
        } catch (err) {
          console.error(`[SocketManager] Error releasing reader for relay ${relayId}:`, err);
        }
      }
    }
  }

  /**
   * Close socket for a relay
   * @param {string} relayId - Relay identifier
   */
  async closeSocket(relayId = 'default') {
    const socketInfo = this.sockets.get(relayId);
    
    if (!socketInfo) {
      console.warn(`[SocketManager] No socket found for relay ${relayId}`);
      return;
    }
    
    console.log(`[SocketManager] Closing socket for relay ${relayId}...`);
    
    // Stop receiving first
    await this.stopReceiving(relayId);
    
    // Close writer
    if (socketInfo.writer) {
      try {
        await socketInfo.writer.close();
        socketInfo.writer = null;
      } catch (err) {
        console.error(`[SocketManager] Error closing writer for relay ${relayId}:`, err);
      }
    }
    
    // Close socket
    if (socketInfo.socket) {
      try {
        await socketInfo.socket.close();
      } catch (err) {
        console.error(`[SocketManager] Error closing socket for relay ${relayId}:`, err);
      }
    }
    
    // Remove from map
    this.sockets.delete(relayId);
    console.log(`[SocketManager] ✓ Socket closed for relay ${relayId}`);
  }

  /**
   * Close all sockets
   */
  async closeAll() {
    console.log('[SocketManager] Closing all sockets...');
    const relayIds = Array.from(this.sockets.keys());
    
    for (const relayId of relayIds) {
      await this.closeSocket(relayId);
    }
    
    console.log('[SocketManager] ✓ All sockets closed');
  }

  /**
   * Get status of all sockets
   */
  getStatus() {
    const status = {};
    
    for (const [relayId, info] of this.sockets.entries()) {
      status[relayId] = {
        localAddress: info.localAddress,
        localPort: info.localPort,
        isReceiving: info.isReceiving,
        hasWriter: !!info.writer,
        hasReader: !!info.reader
      };
    }
    
    return {
      totalSockets: this.sockets.size,
      totalPackets: this.packetCount,
      sockets: status
    };
  }
}

export const socketManager = new SocketManager();


