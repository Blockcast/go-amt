// service-worker.js
// Clean Service Worker with Direct Sockets API for IWA
// Direct Sockets ONLY works in Service Workers, not main window!
'use strict';

// Import socket manager
import { socketManager } from './sw-socket-manager.js';

// Import output servers
import { serverManager } from './output-servers/server-manager.js';
import { LocalUDPServer } from './output-servers/udp-server.js';
import { LocalWebSocketServer } from './output-servers/websocket-server.js';

// Import packet parser for (S,G) extraction
import { parsePacketMetadata, formatSG } from './packet-parser.js';

// Service Worker version - automatically injected from package.json at build time
const SW_VERSION = __APP_VERSION__;

// PERFORMANCE OPTIMIZATION: Cache parsed metadata per relay
// Avoids parsing 7000+ packets when we only need to parse once!
const cachedMetadata = new Map(); // relayId -> { sourceIP, groupIP, port }

self.addEventListener('install', (event) => {
  console.log('[SW] Installing...');
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  console.log(`[SW] Activating (v${SW_VERSION})...`);
  event.waitUntil(
    (async () => {
      await self.clients.claim();
      
      // Check Direct Sockets availability
      console.log('[SW] Checking Direct Sockets API...');
      console.log(`[SW]   UDPSocket: ${typeof UDPSocket !== 'undefined' ? 'Available' : 'NOT AVAILABLE'}`);
      console.log(`[SW]   TCPServerSocket: ${typeof TCPServerSocket !== 'undefined' ? 'Available' : 'NOT AVAILABLE'}`);
      
      // Initialize output servers using Direct Sockets API
      if (typeof UDPSocket !== 'undefined' || typeof TCPServerSocket !== 'undefined') {
        console.log('[SW] Initializing output servers...');
        
        try {
          // Register servers
          const udpServer = new LocalUDPServer();
          const wsServer = new LocalWebSocketServer();
          
          serverManager.registerServer('udp', udpServer);
          serverManager.registerServer('websocket', wsServer);
          
          // Start servers
          const results = await serverManager.startAll();
          
          const successCount = Object.values(results).filter(r => r.success).length;
          console.log(`[SW] ✓ Started ${successCount}/${Object.keys(results).length} output servers`);
          console.log('[SW] ✓ Output servers running (Direct Sockets API)');
        } catch (error) {
          console.error('[SW] Failed to start output servers:', error);
          console.log('[SW] ⚠️ Falling back to direct streaming only');
        }
      } else {
        console.log('[SW] ⚠️ Direct Sockets API not available, using direct streaming only');
      }
      
      console.log('[SW] ✓ Service Worker ready');
    })()
  );
});

self.addEventListener('fetch', (event) => {
  // For IWA, bypass service worker completely - let browser handle it
  // This prevents CSP caching issues
  return;
});

// Handle messages from main page
self.addEventListener('message', async (event) => {
  // Handle SKIP_WAITING message for updates
  if (event.data && event.data.type === 'SKIP_WAITING') {
    console.log(`[SW v${SW_VERSION}] SKIP_WAITING received, activating...`);
    self.skipWaiting();
    return;
  }
  
  const { type, data } = event.data;
  
  console.log(`[SW v${SW_VERSION}] Received message:`, type);
  
  try {
    switch (type) {
      case 'CHECK_API':
        const available = typeof UDPSocket !== 'undefined';
        console.log('[SW] CHECK_API: Direct streaming mode');
        
        event.ports[0].postMessage({ 
          success: true, 
          available,
          hasUDP: typeof UDPSocket !== 'undefined',
          hasTCP: typeof TCPSocket !== 'undefined'
        });
        break;
        
      case 'CREATE_SOCKET': {
        const relayId = data?.relayId || 'default';
        const socketInfo = await socketManager.createSocket(relayId);
        
        // Notify all clients about the new socket
        const clients = await self.clients.matchAll();
        clients.forEach(client => {
          client.postMessage({
            type: 'SOCKET_CREATED',
            data: socketInfo
          });
        });
        
        event.ports[0].postMessage({ success: true, data: socketInfo });
        break;
      }
        
      case 'SEND_UDP': {
        const relayId = data?.relayId || 'default';
        await socketManager.sendUDP(data.buffer, data.remoteAddress, data.remotePort, relayId);
        event.ports[0].postMessage({ success: true });
        break;
      }
        
      case 'START_RECEIVE': {
        const relayId = data?.relayId || 'default';
        
        // Start receiving with callback to forward packets to app AND output servers
        await socketManager.startReceiving(relayId, async (packet, remoteAddress, remotePort, relayId) => {
          // Forward packet to all clients for MediaSource playback (direct streaming)
          const clients = await self.clients.matchAll();
          clients.forEach(client => {
            client.postMessage({
              type: 'UDP_PACKET',
              data: Array.from(packet),
              remoteAddress: remoteAddress || '0.0.0.0',
              remotePort: remotePort || 0,
              size: packet.length,
              relayId
            });
          });
          
        // ALSO forward to output servers for external clients
        if (serverManager.enabled) {
          // PERFORMANCE: Parse metadata once per relay, cache for all subsequent packets
          // This avoids 7000+ parsing operations (byte scanning, array allocs, string concat)
          let metadata = cachedMetadata.get(relayId);
          
          if (!metadata) {
            // First packet for this relay - parse and cache
            metadata = parsePacketMetadata(packet);
            if (metadata.sourceIP && metadata.groupIP) {
              cachedMetadata.set(relayId, metadata);
              console.log(`[SW] Cached metadata for ${relayId}: ${formatSG(metadata.sourceIP, metadata.groupIP, metadata.port)}`);
            }
          }
          
          // Log periodically (but use cached metadata!)
          if (socketManager.packetCount % 1000 === 0 && metadata.sourceIP) {
            console.log(`[SW] (S,G): ${formatSG(metadata.sourceIP, metadata.groupIP, metadata.port)} [cached]`);
          }
          
          // Forward with real (S,G) metadata from cache
          await serverManager.handleIncomingPacket(
            packet, 
            metadata.sourceIP || '*',
            metadata.groupIP || '*',
            metadata.port || 0
          );
        }
        });
        
        event.ports[0].postMessage({ success: true });
        break;
      }
        
      case 'STOP_RECEIVE': {
        const relayId = data?.relayId || 'default';
        await socketManager.stopReceiving(relayId);
        event.ports[0].postMessage({ success: true });
        break;
      }
        
      case 'CLOSE_SOCKET': {
        const relayId = data?.relayId;
        
        if (relayId) {
          await socketManager.closeSocket(relayId);
          // Clear cached metadata for this relay
          cachedMetadata.delete(relayId);
        } else {
          // Close all if no specific relay
          await socketManager.closeAll();
          // Clear all cached metadata
          cachedMetadata.clear();
        }
        
        event.ports[0].postMessage({ success: true });
        break;
      }
      
      case 'GET_SERVER_STATUS': {
        // Return both socket manager AND output servers status
        const socketStatus = socketManager.getStatus();
        const serverStatus = serverManager.getStatus();
        
        event.ports[0].postMessage({
          success: true,
          mode: 'hybrid', // Direct streaming + output servers
          directStreaming: socketStatus,
          outputServers: serverStatus,
          serversEnabled: serverManager.enabled,
          serverCount: serverManager.getEnabledServerCount()
        });
        break;
      }
      
      case 'GET_SERVER_HEALTH': {
        // Return health status (simplified for direct streaming)
        const status = socketManager.getStatus();
        event.ports[0].postMessage({
          success: true,
          healthy: status.totalSockets > 0,
          socketCount: status.totalSockets,
          packetCount: status.totalPackets
        });
        break;
      }
      
      case 'INJECT_TEST_PACKET': {
        // For testing: inject a packet directly
        const { payload, relayId } = data;
        const packet = new Uint8Array(payload);
        
        // Forward to all clients
        const clients = await self.clients.matchAll();
        clients.forEach(client => {
          client.postMessage({
            type: 'UDP_PACKET',
            data: Array.from(packet),
            remoteAddress: '127.0.0.1',
            remotePort: 0,
            size: packet.length,
            relayId: relayId || 'test'
          });
        });
        
        event.ports[0].postMessage({ 
          success: true,
          forwarded: true,
          note: 'Test packet injected into direct streaming pipeline'
        });
        break;
      }
        
      default:
        event.ports[0].postMessage({ success: false, error: 'Unknown command' });
    }
  } catch (error) {
    console.error('[SW] Error:', error);
    event.ports[0].postMessage({ success: false, error: error.message });
  }
});

console.log(`[SW v${SW_VERSION}] Service Worker loaded with Direct Sockets support`);
