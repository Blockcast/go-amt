// tcp-server.js
// TCP/HTTP Output Server using Direct Sockets API
// Implements HTTP chunked transfer encoding for multicast forwarding

import { DEFAULT_CONFIG, WILDCARD } from '../constants.js';

export class LocalTCPServer {
  constructor() {
    this.serverSocket = null;
    this.clients = new Map(); // clientId → { socket, filter, active, writer }
    this.enabled = false;
    this.port = DEFAULT_CONFIG.TCP_HTTP_PORT;
    this.clientIdCounter = 0;
  }
  
  /**
   * Start TCP/HTTP server using Direct Sockets API
   */
  async start(port = DEFAULT_CONFIG.TCP_HTTP_PORT) {
    console.log(`[TCP Server] Starting on port ${port} (no localAddress)...`);
    
    try {
      // Create TCP server socket (Direct Sockets API)
      // TCPServerSocket does NOT accept localAddress in Service Workers - only localPort
      this.serverSocket = new TCPServerSocket(port);
      
      // Wait for server to be ready
      const serverInfo = await this.serverSocket.opened;
      console.log(`[TCP Server] ✓ Listening on ${serverInfo.localAddress}:${serverInfo.localPort}`);
      
      // Start accepting connections
      this.acceptConnections();
      
      this.enabled = true;
      console.log('[TCP Server] ✓ Started');
      
      return true;
    } catch (error) {
      console.error('[TCP Server] Failed to start:', error);
      throw error;
    }
  }
  
  /**
   * Stop TCP server
   */
  async stop() {
    if (!this.enabled) return;
    
    console.log('[TCP Server] Stopping...');
    
    // Close all client connections
    for (const [clientId, client] of this.clients) {
      await this.closeClient(clientId);
    }
    this.clients.clear();
    
    // Close server socket
    if (this.serverSocket) {
      await this.serverSocket.close();
      this.serverSocket = null;
    }
    
    this.enabled = false;
    console.log('[TCP Server] ✓ Stopped');
  }
  
  /**
   * Accept incoming connections
   */
  async acceptConnections() {
    const { readable } = await this.serverSocket.opened;
    const reader = readable.getReader();
    
    try {
      while (this.enabled) {
        const { value, done } = await reader.read();
        
        if (done) {
          console.log('[TCP Server] Server socket closed');
          break;
        }
        
        // value is TCPSocket for the new connection
        const clientSocket = value;
        await this.handleConnection(clientSocket);
      }
    } catch (error) {
      if (this.enabled) {
        console.error('[TCP Server] Accept error:', error);
      }
    } finally {
      reader.releaseLock();
    }
  }
  
  /**
   * Handle new client connection
   */
  async handleConnection(clientSocket) {
    const clientId = ++this.clientIdCounter;
    console.log(`[TCP Server] Client ${clientId} connected`);
    
    try {
      // Get socket info
      const socketInfo = await clientSocket.opened;
      
      // First, we need to read the HTTP request to get the path/query
      const { readable, writable } = socketInfo;
      const reader = readable.getReader();
      
      // Read HTTP request headers
      let requestData = '';
      let filter = {
        source: WILDCARD.SOURCE,
        group: WILDCARD.GROUP,
        port: WILDCARD.PORT
      };
      
      // Read request line
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        
        requestData += new TextDecoder().decode(value);
        
        // Check if we have complete headers (double CRLF)
        if (requestData.includes('\r\n\r\n')) {
          // Parse request line
          const lines = requestData.split('\r\n');
          const requestLine = lines[0];
          const match = requestLine.match(/^GET\s+(\S+)\s+HTTP/);
          
          if (match) {
            const path = match[1];
            filter = this.parseFilter(path);
          }
          
          break;
        }
      }
      
      reader.releaseLock();
      
      // Send HTTP headers
      const headers = 
        'HTTP/1.1 200 OK\r\n' +
        'Content-Type: application/octet-stream\r\n' +
        'Transfer-Encoding: chunked\r\n' +
        'Access-Control-Allow-Origin: *\r\n' +
        'Cache-Control: no-cache\r\n' +
        'X-AMT-Gateway: true\r\n' +
        (filter.source !== WILDCARD.SOURCE ? `X-Stream-Source: ${filter.source}\r\n` : '') +
        (filter.group !== WILDCARD.GROUP ? `X-Stream-Group: ${filter.group}\r\n` : '') +
        (filter.port !== WILDCARD.PORT ? `X-Stream-Port: ${filter.port}\r\n` : '') +
        '\r\n';
      
      const writer = writable.getWriter();
      await writer.write(new TextEncoder().encode(headers));
      
      // Store client
      this.clients.set(clientId, {
        socket: clientSocket,
        filter,
        active: true,
        writer
      });
      
      console.log(`[TCP Server] ✓ Client ${clientId} subscribed (filter: ${JSON.stringify(filter)})`);
      
      // Monitor for disconnection
      this.monitorClient(clientId, clientSocket);
      
    } catch (error) {
      console.error(`[TCP Server] Failed to handle client ${clientId}:`, error);
      await this.closeClient(clientId);
    }
  }
  
  /**
   * Parse filter from URL path or query parameters
   */
  parseFilter(path) {
    const filter = {
      source: WILDCARD.SOURCE,
      group: WILDCARD.GROUP,
      port: WILDCARD.PORT
    };
    
    // Try path format: /stream/{source}/{group}/{port}
    const pathMatch = path.match(/^\/stream\/([^\/\?]+)\/([^\/\?]+)\/([^\/\?]+)/);
    if (pathMatch) {
      filter.source = pathMatch[1] === '*' ? WILDCARD.SOURCE : pathMatch[1];
      filter.group = pathMatch[2] === '*' ? WILDCARD.GROUP : pathMatch[2];
      filter.port = pathMatch[3] === '*' ? WILDCARD.PORT : parseInt(pathMatch[3]);
      return filter;
    }
    
    // Try query parameters: /stream?source=X&group=Y&port=Z
    const queryMatch = path.match(/\?(.+)$/);
    if (queryMatch) {
      const params = new URLSearchParams(queryMatch[1]);
      filter.source = params.get('source') || WILDCARD.SOURCE;
      if (filter.source === '*') filter.source = WILDCARD.SOURCE;
      
      filter.group = params.get('group') || WILDCARD.GROUP;
      if (filter.group === '*') filter.group = WILDCARD.GROUP;
      
      const portParam = params.get('port');
      if (portParam && portParam !== '*') {
        filter.port = parseInt(portParam);
      }
    }
    
    return filter;
  }
  
  /**
   * Monitor client for disconnection
   */
  async monitorClient(clientId, clientSocket) {
    try {
      await clientSocket.closed;
      console.log(`[TCP Server] Client ${clientId} disconnected`);
      this.clients.delete(clientId);
    } catch (error) {
      console.error(`[TCP Server] Client ${clientId} error:`, error);
      this.clients.delete(clientId);
    }
  }
  
  /**
   * Close client connection
   */
  async closeClient(clientId) {
    const client = this.clients.get(clientId);
    if (!client) return;
    
    try {
      if (client.writer) {
        await client.writer.close();
      }
      if (client.socket) {
        await client.socket.close();
      }
    } catch (error) {
      console.error(`[TCP Server] Error closing client ${clientId}:`, error);
    }
    
    this.clients.delete(clientId);
  }
  
  /**
   * Broadcast packet to all subscribed clients
   */
  async broadcastPacket(rawPayload, sourceIP, groupIP, groupPort) {
    if (!this.enabled || this.clients.size === 0) {
      return 0;
    }
    
    let sentCount = 0;
    
    for (const [clientId, client] of this.clients) {
      if (client.active && this.matchesFilter(client.filter, sourceIP, groupIP, groupPort)) {
        await this.sendChunk(clientId, rawPayload);
        sentCount++;
      }
    }
    
    return sentCount;
  }
  
  /**
   * Send data as HTTP chunk
   */
  async sendChunk(clientId, data) {
    const client = this.clients.get(clientId);
    if (!client || !client.writer) return;
    
    try {
      // HTTP chunk format: size_in_hex\r\ndata\r\n
      const size = data.byteLength || data.length;
      const sizeHex = size.toString(16);
      
      const chunkHeader = new TextEncoder().encode(`${sizeHex}\r\n`);
      const chunkFooter = new TextEncoder().encode('\r\n');
      
      // Ensure data is ArrayBuffer
      const buffer = data instanceof ArrayBuffer ? data : 
                     data.buffer ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) :
                     new Uint8Array(data).buffer;
      
      // Send chunk: header + data + footer
      await client.writer.write(chunkHeader);
      await client.writer.write(buffer);
      await client.writer.write(chunkFooter);
      
    } catch (error) {
      // Client disconnected or error
      console.warn(`[TCP Server] Failed to send chunk to client ${clientId}:`, error);
      client.active = false;
      await this.closeClient(clientId);
    }
  }
  
  /**
   * Check if packet matches filter
   */
  matchesFilter(filter, sourceIP, groupIP, groupPort) {
    const sourceMatch = filter.source === WILDCARD.SOURCE || filter.source === sourceIP;
    const groupMatch = filter.group === WILDCARD.GROUP || filter.group === groupIP;
    const portMatch = filter.port === WILDCARD.PORT || filter.port == groupPort;
    return sourceMatch && groupMatch && portMatch;
  }
  
  /**
   * Get server status
   */
  getStatus() {
    return {
      enabled: this.enabled,
      port: this.port,
      clients: this.clients.size
    };
  }
}

// Export singleton instance
export const tcpServer = new LocalTCPServer();



