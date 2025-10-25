/**
 * WebSocket Output Server
 * 
 * WebSocket server for web-based clients. Uses TCP sockets from Direct Sockets API
 * with WebSocket protocol implementation (RFC 6455).
 * 
 * Features:
 * - WebSocket handshake (HTTP upgrade)
 * - Frame encoding/decoding
 * - Text and binary frames
 * - Subscription management per client
 * - Filtered packet broadcasting
 * 
 * Note: This is a simplified WebSocket implementation focused on our use case.
 * For production, consider a full WebSocket library if available in Service Workers.
 */

import { DEFAULT_CONFIG, WILDCARD } from '../constants.js';
// Note: We use Web Crypto API (crypto.subtle) for WebSocket handshake
// Available globally in Service Worker context

export class LocalWebSocketServer {
  constructor() {
    this.serverSocketId = null;
    this.clients = new Map(); // clientSocketId -> client info
    this.enabled = false;
    
    // Statistics
    this.stats = {
      totalConnections: 0,
      activeConnections: 0,
      messagesReceived: 0,
      messagesSent: 0,
      bytesReceived: 0,
      bytesSent: 0
    };

    // WebSocket magic string for handshake
    this.WS_MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
  }

  /**
   * Start WebSocket server
   * 
   * @param {number} port - Port to listen on (default: 5002)
   * @param {string} address - Address to bind (default: '0.0.0.0')
   * @returns {Promise<boolean>} Success
   */
  async start(port = DEFAULT_CONFIG.WEBSOCKET_PORT || 5002, address = '0.0.0.0') {
    console.log(`[WebSocket] Starting server on ${address}:${port}...`);

    try {
      // Create TCP server socket
      this.serverSocketId = await this.createSocket();
      
      // Bind and listen
      await this.bindSocket(this.serverSocketId, address, port);
      await this.listenSocket(this.serverSocketId, address, port, 10);
      
      // Setup connection handler
      this.setupConnectionHandler();
      
      this.enabled = true;
      
      console.log(`[WebSocket] ✓ Server listening on ${address}:${port}`);
      return true;
      
    } catch (error) {
      console.error('[WebSocket] Failed to start:', error);
      throw error;
    }
  }

  /**
   * Stop WebSocket server
   * 
   * @returns {Promise<boolean>} Success
   */
  async stop() {
    console.log('[WebSocket] Stopping server...');

    try {
      // Close all client connections
      for (const [clientSocketId] of this.clients.entries()) {
        await this.closeClient(clientSocketId);
      }
      
      // Close server socket
      if (this.serverSocketId !== null) {
        await this.closeSocket(this.serverSocketId);
        this.serverSocketId = null;
      }
      
      this.clients.clear();
      this.enabled = false;
      
      console.log('[WebSocket] ✓ Server stopped');
      return true;
      
    } catch (error) {
      console.error('[WebSocket] Error stopping:', error);
      return false;
    }
  }

  /**
   * Setup handler for incoming connections
   */
  setupConnectionHandler() {
    chrome.sockets.tcp.onAccept.addListener((info) => {
      if (info.socketId === this.serverSocketId) {
        this.handleNewConnection(info.clientSocketId);
      }
    });
  }

  /**
   * Handle new WebSocket connection
   * 
   * @param {number} clientSocketId - Client socket ID
   */
  async handleNewConnection(clientSocketId) {
    console.log(`[WebSocket] New connection: ${clientSocketId}`);

    try {
      // Store client info
      this.clients.set(clientSocketId, {
        socketId: clientSocketId,
        state: 'handshake', // handshake -> connected -> closed
        filter: { source: WILDCARD.SOURCE, group: WILDCARD.GROUP, port: WILDCARD.PORT },
        buffer: new Uint8Array(0),
        connectedAt: Date.now()
      });

      this.stats.totalConnections++;

      // Setup receive handler for this client
      this.setupClientReceiveHandler(clientSocketId);
      
    } catch (error) {
      console.error(`[WebSocket] Error handling new connection:`, error);
      await this.closeClient(clientSocketId);
    }
  }

  /**
   * Setup receive handler for client
   * 
   * @param {number} clientSocketId - Client socket ID
   */
  setupClientReceiveHandler(clientSocketId) {
    chrome.sockets.tcp.onReceive.addListener((info) => {
      if (info.socketId === clientSocketId) {
        this.handleClientData(clientSocketId, new Uint8Array(info.data));
      }
    });

    chrome.sockets.tcp.onReceiveError.addListener((info) => {
      if (info.socketId === clientSocketId) {
        console.error(`[WebSocket] Client ${clientSocketId} error: ${info.resultCode}`);
        this.closeClient(clientSocketId);
      }
    });
  }

  /**
   * Handle data received from client
   * 
   * @param {number} clientSocketId - Client socket ID
   * @param {Uint8Array} data - Received data
   */
  async handleClientData(clientSocketId, data) {
    const client = this.clients.get(clientSocketId);
    if (!client) return;

    try {
      this.stats.bytesReceived += data.length;

      // Append to buffer
      const newBuffer = new Uint8Array(client.buffer.length + data.length);
      newBuffer.set(client.buffer);
      newBuffer.set(data, client.buffer.length);
      client.buffer = newBuffer;

      if (client.state === 'handshake') {
        // Try to parse HTTP upgrade request
        await this.handleHandshake(clientSocketId);
      } else if (client.state === 'connected') {
        // Parse WebSocket frames
        await this.handleWebSocketFrames(clientSocketId);
      }
      
    } catch (error) {
      console.error(`[WebSocket] Error handling client data:`, error);
      await this.closeClient(clientSocketId);
    }
  }

  /**
   * Handle WebSocket handshake
   * 
   * @param {number} clientSocketId - Client socket ID
   */
  async handleHandshake(clientSocketId) {
    const client = this.clients.get(clientSocketId);
    if (!client) return;

    // Convert buffer to string to parse HTTP headers
    const text = new TextDecoder().decode(client.buffer);
    
    // Check if we have complete headers (ends with \r\n\r\n)
    if (!text.includes('\r\n\r\n')) {
      return; // Wait for more data
    }

    // Parse HTTP headers
    const lines = text.split('\r\n');
    const headers = {};
    
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (!line) break;
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.substring(0, colonIndex).trim().toLowerCase();
        const value = line.substring(colonIndex + 1).trim();
        headers[key] = value;
      }
    }

    // Validate WebSocket upgrade request
    if (headers['upgrade'] !== 'websocket' || 
        !headers['sec-websocket-key']) {
      console.error('[WebSocket] Invalid upgrade request');
      await this.closeClient(clientSocketId);
      return;
    }

    // Generate accept key
    const acceptKey = await this.generateAcceptKey(headers['sec-websocket-key']);

    // Send handshake response
    const response = [
      'HTTP/1.1 101 Switching Protocols',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Accept: ${acceptKey}`,
      '',
      ''
    ].join('\r\n');

    await this.sendToClient(clientSocketId, new TextEncoder().encode(response));

    // Update client state
    client.state = 'connected';
    client.buffer = new Uint8Array(0); // Clear handshake data
    this.stats.activeConnections++;

    console.log(`[WebSocket] Client ${clientSocketId} connected`);
  }

  /**
   * Generate WebSocket accept key for handshake
   * 
   * @param {string} clientKey - Client's Sec-WebSocket-Key
   * @returns {Promise<string>} Accept key
   */
  async generateAcceptKey(clientKey) {
    try {
      // In Service Worker context, we might not have crypto.subtle
      // This is a simplified version - in production, use proper SHA-1
      const combined = clientKey + this.WS_MAGIC_STRING;
      
      // If crypto.subtle is available
      if (typeof crypto !== 'undefined' && crypto.subtle) {
        const encoder = new TextEncoder();
        const data = encoder.encode(combined);
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashBase64 = btoa(String.fromCharCode.apply(null, hashArray));
        return hashBase64;
      }
      
      // Fallback: return a mock key (for testing)
      // In production, this MUST use proper SHA-1 hashing
      return btoa(combined).substring(0, 28);
      
    } catch (error) {
      console.error('[WebSocket] Error generating accept key:', error);
      // Return a simple base64 encoding as fallback
      return btoa(clientKey + this.WS_MAGIC_STRING).substring(0, 28);
    }
  }

  /**
   * Handle WebSocket frames
   * 
   * @param {number} clientSocketId - Client socket ID
   */
  async handleWebSocketFrames(clientSocketId) {
    const client = this.clients.get(clientSocketId);
    if (!client || client.buffer.length < 2) return;

    try {
      while (client.buffer.length >= 2) {
        // Parse frame header
        const firstByte = client.buffer[0];
        const secondByte = client.buffer[1];

        const fin = (firstByte & 0x80) !== 0;
        const opcode = firstByte & 0x0F;
        const masked = (secondByte & 0x80) !== 0;
        let payloadLength = secondByte & 0x7F;

        let offset = 2;

        // Handle extended payload length
        if (payloadLength === 126) {
          if (client.buffer.length < 4) return; // Need more data
          payloadLength = (client.buffer[2] << 8) | client.buffer[3];
          offset = 4;
        } else if (payloadLength === 127) {
          if (client.buffer.length < 10) return; // Need more data
          // For simplicity, we don't handle 64-bit lengths
          offset = 10;
        }

        // Get masking key if present
        let maskingKey;
        if (masked) {
          if (client.buffer.length < offset + 4) return; // Need more data
          maskingKey = client.buffer.slice(offset, offset + 4);
          offset += 4;
        }

        // Check if we have complete frame
        if (client.buffer.length < offset + payloadLength) {
          return; // Wait for more data
        }

        // Extract payload
        let payload = client.buffer.slice(offset, offset + payloadLength);

        // Unmask payload if needed
        if (masked && maskingKey) {
          payload = this.unmaskPayload(payload, maskingKey);
        }

        // Remove processed frame from buffer
        client.buffer = client.buffer.slice(offset + payloadLength);

        // Handle frame based on opcode
        await this.handleFrame(clientSocketId, opcode, payload);
      }
    } catch (error) {
      console.error('[WebSocket] Error handling frames:', error);
      await this.closeClient(clientSocketId);
    }
  }

  /**
   * Unmask WebSocket payload
   * 
   * @param {Uint8Array} payload - Masked payload
   * @param {Uint8Array} maskingKey - 4-byte masking key
   * @returns {Uint8Array} Unmasked payload
   */
  unmaskPayload(payload, maskingKey) {
    const unmasked = new Uint8Array(payload.length);
    for (let i = 0; i < payload.length; i++) {
      unmasked[i] = payload[i] ^ maskingKey[i % 4];
    }
    return unmasked;
  }

  /**
   * Handle WebSocket frame
   * 
   * @param {number} clientSocketId - Client socket ID
   * @param {number} opcode - Frame opcode
   * @param {Uint8Array} payload - Frame payload
   */
  async handleFrame(clientSocketId, opcode, payload) {
    const client = this.clients.get(clientSocketId);
    if (!client) return;

    this.stats.messagesReceived++;

    switch (opcode) {
      case 0x1: // Text frame
        await this.handleTextMessage(clientSocketId, payload);
        break;
        
      case 0x2: // Binary frame
        // We primarily send binary, don't expect to receive it
        console.log(`[WebSocket] Received binary frame from ${clientSocketId}`);
        break;
        
      case 0x8: // Close frame
        console.log(`[WebSocket] Client ${clientSocketId} sent close frame`);
        await this.closeClient(clientSocketId);
        break;
        
      case 0x9: // Ping frame
        // Respond with pong
        await this.sendPong(clientSocketId, payload);
        break;
        
      case 0xA: // Pong frame
        // Received pong, update last activity
        client.lastActivity = Date.now();
        break;
        
      default:
        console.warn(`[WebSocket] Unknown opcode: ${opcode}`);
    }
  }

  /**
   * Handle text message from client
   * 
   * @param {number} clientSocketId - Client socket ID
   * @param {Uint8Array} payload - Message payload
   */
  async handleTextMessage(clientSocketId, payload) {
    const client = this.clients.get(clientSocketId);
    if (!client) return;

    try {
      const text = new TextDecoder().decode(payload);
      const message = JSON.parse(text);

      console.log(`[WebSocket] Message from ${clientSocketId}:`, message.type);

      switch (message.type) {
        case 'subscribe':
          client.filter = {
            source: message.source || WILDCARD.SOURCE,
            group: message.group || WILDCARD.GROUP,
            port: message.port || WILDCARD.PORT
          };
          console.log(`[WebSocket] Client ${clientSocketId} subscribed:`, client.filter);
          
          // Send confirmation
          await this.sendTextMessage(clientSocketId, JSON.stringify({
            type: 'subscribed',
            filter: client.filter
          }));
          break;

        case 'unsubscribe':
          client.filter = {
            source: WILDCARD.SOURCE,
            group: WILDCARD.GROUP,
            port: WILDCARD.PORT
          };
          console.log(`[WebSocket] Client ${clientSocketId} unsubscribed`);
          break;

        case 'ping':
          await this.sendTextMessage(clientSocketId, JSON.stringify({ type: 'pong' }));
          break;

        default:
          console.warn(`[WebSocket] Unknown message type: ${message.type}`);
      }
      
    } catch (error) {
      console.error('[WebSocket] Error handling text message:', error);
    }
  }

  /**
   * Broadcast packet to subscribed WebSocket clients
   * 
   * @param {Uint8Array} packet - Raw packet data
   * @param {string} sourceIP - Source IP
   * @param {string} groupIP - Multicast group IP
   * @param {number} port - Port number
   * @returns {Promise<number>} Number of clients sent to
   */
  async broadcastPacket(packet, sourceIP, groupIP, port) {
    if (!this.enabled) return 0;

    let sentCount = 0;

    for (const [clientSocketId, client] of this.clients.entries()) {
      if (client.state !== 'connected') continue;

      // Check if client's filter matches this stream
      if (this.matchesFilter(client.filter, sourceIP, groupIP, port)) {
        try {
          await this.sendBinaryFrame(clientSocketId, packet);
          sentCount++;
        } catch (error) {
          console.error(`[WebSocket] Error sending to client ${clientSocketId}:`, error);
          await this.closeClient(clientSocketId);
        }
      }
    }

    return sentCount;
  }

  /**
   * Check if filter matches stream
   * 
   * @param {Object} filter - Subscription filter
   * @param {string} sourceIP - Source IP
   * @param {string} groupIP - Group IP
   * @param {number} port - Port
   * @returns {boolean} Match result
   */
  matchesFilter(filter, sourceIP, groupIP, port) {
    const sourceMatch = filter.source === WILDCARD.SOURCE || filter.source === sourceIP;
    const groupMatch = filter.group === WILDCARD.GROUP || filter.group === groupIP;
    const portMatch = filter.port === WILDCARD.PORT || String(filter.port) === String(port);
    return sourceMatch && groupMatch && portMatch;
  }

  /**
   * Send binary WebSocket frame
   * 
   * @param {number} clientSocketId - Client socket ID
   * @param {Uint8Array} data - Binary data
   */
  async sendBinaryFrame(clientSocketId, data) {
    const frame = this.encodeFrame(0x82, data); // 0x82 = FIN + binary opcode
    await this.sendToClient(clientSocketId, frame);
    this.stats.messagesSent++;
    this.stats.bytesSent += data.length;
  }

  /**
   * Send text message to client
   * 
   * @param {number} clientSocketId - Client socket ID
   * @param {string} text - Text message
   */
  async sendTextMessage(clientSocketId, text) {
    const payload = new TextEncoder().encode(text);
    const frame = this.encodeFrame(0x81, payload); // 0x81 = FIN + text opcode
    await this.sendToClient(clientSocketId, frame);
    this.stats.messagesSent++;
  }

  /**
   * Send pong frame
   * 
   * @param {number} clientSocketId - Client socket ID
   * @param {Uint8Array} payload - Ping payload to echo
   */
  async sendPong(clientSocketId, payload) {
    const frame = this.encodeFrame(0x8A, payload); // 0x8A = FIN + pong opcode
    await this.sendToClient(clientSocketId, frame);
  }

  /**
   * Encode WebSocket frame
   * 
   * @param {number} firstByte - First byte (FIN + opcode)
   * @param {Uint8Array} payload - Payload data
   * @returns {Uint8Array} Encoded frame
   */
  encodeFrame(firstByte, payload) {
    const payloadLength = payload.length;
    let frame;
    let offset;

    if (payloadLength < 126) {
      frame = new Uint8Array(2 + payloadLength);
      frame[0] = firstByte;
      frame[1] = payloadLength;
      offset = 2;
    } else if (payloadLength < 65536) {
      frame = new Uint8Array(4 + payloadLength);
      frame[0] = firstByte;
      frame[1] = 126;
      frame[2] = (payloadLength >> 8) & 0xFF;
      frame[3] = payloadLength & 0xFF;
      offset = 4;
    } else {
      // For very large payloads (we shouldn't hit this)
      frame = new Uint8Array(10 + payloadLength);
      frame[0] = firstByte;
      frame[1] = 127;
      // Set 64-bit length (simplified - just use lower 32 bits)
      for (let i = 2; i < 10; i++) frame[i] = 0;
      frame[6] = (payloadLength >> 24) & 0xFF;
      frame[7] = (payloadLength >> 16) & 0xFF;
      frame[8] = (payloadLength >> 8) & 0xFF;
      frame[9] = payloadLength & 0xFF;
      offset = 10;
    }

    frame.set(payload, offset);
    return frame;
  }

  /**
   * Send data to client
   * 
   * @param {number} clientSocketId - Client socket ID
   * @param {Uint8Array} data - Data to send
   */
  async sendToClient(clientSocketId, data) {
    return new Promise((resolve, reject) => {
      chrome.sockets.tcp.send(clientSocketId, data.buffer, (sendInfo) => {
        if (sendInfo.resultCode < 0) {
          reject(new Error(`Send failed: ${sendInfo.resultCode}`));
        } else {
          resolve();
        }
      });
    });
  }

  /**
   * Close client connection
   * 
   * @param {number} clientSocketId - Client socket ID
   */
  async closeClient(clientSocketId) {
    const client = this.clients.get(clientSocketId);
    if (!client) return;

    console.log(`[WebSocket] Closing client ${clientSocketId}`);

    try {
      // Send close frame if still connected
      if (client.state === 'connected') {
        const closeFrame = this.encodeFrame(0x88, new Uint8Array(0)); // 0x88 = close opcode
        await this.sendToClient(clientSocketId, closeFrame).catch(() => {});
      }

      // Close socket
      await this.closeSocket(clientSocketId);

      // Remove from clients
      this.clients.delete(clientSocketId);
      
      if (client.state === 'connected') {
        this.stats.activeConnections--;
      }
      
    } catch (error) {
      console.error(`[WebSocket] Error closing client:`, error);
    }
  }

  /**
   * Get server status
   * 
   * @returns {Object} Status object
   */
  getStatus() {
    return {
      enabled: this.enabled,
      port: DEFAULT_CONFIG.WEBSOCKET_PORT || 5002,
      clients: this.clients.size,
      activeConnections: this.stats.activeConnections,
      ...this.stats
    };
  }

  /**
   * Get statistics
   * 
   * @returns {Object} Statistics object
   */
  getStats() {
    return { ...this.stats };
  }

  /**
   * Check if server is healthy
   * 
   * @returns {boolean} Health status
   */
  isHealthy() {
    return this.enabled && this.serverSocketId !== null;
  }

  // Chrome TCP Socket helpers (promise wrappers)

  createSocket() {
    return new Promise((resolve, reject) => {
      chrome.sockets.tcp.create({}, (createInfo) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(createInfo.socketId);
        }
      });
    });
  }

  bindSocket(socketId, address, port) {
    return new Promise((resolve, reject) => {
      chrome.sockets.tcp.bind(socketId, address, port, (result) => {
        if (result < 0) {
          reject(new Error(`Bind failed: ${result}`));
        } else {
          resolve();
        }
      });
    });
  }

  listenSocket(socketId, address, port, backlog) {
    return new Promise((resolve, reject) => {
      chrome.sockets.tcp.listen(socketId, address, port, backlog, (result) => {
        if (result < 0) {
          reject(new Error(`Listen failed: ${result}`));
        } else {
          resolve();
        }
      });
    });
  }

  closeSocket(socketId) {
    return new Promise((resolve) => {
      chrome.sockets.tcp.close(socketId, () => {
        resolve();
      });
    });
  }
}

// Export singleton instance
export const websocketServer = new LocalWebSocketServer();

