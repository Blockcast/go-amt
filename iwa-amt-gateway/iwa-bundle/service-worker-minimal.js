// Minimal service worker for IWA with Direct Sockets
'use strict';

console.log('[SW] Service Worker starting...');

// Check Direct Sockets availability
console.log('[SW] UDPSocket available:', typeof UDPSocket !== 'undefined');
console.log('[SW] TCPSocket available:', typeof TCPSocket !== 'undefined');

let udpSocket = null;

self.addEventListener('install', (event) => {
  console.log('[SW] Installing...');
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  console.log('[SW] Activating...');
  event.waitUntil(self.clients.claim());
});

// Handle messages from main page
self.addEventListener('message', (event) => {
  const { type, data } = event.data;
  const port = event.ports[0];
  
  console.log('[SW] Received message:', type);
  
  switch (type) {
    case 'CHECK_API':
      port.postMessage({
        success: true,
        available: true,
        hasUDP: typeof UDPSocket !== 'undefined',
        hasTCP: typeof TCPSocket !== 'undefined'
      });
      break;
      
    case 'CREATE_SOCKET':
      createUDPSocket(port);
      break;
      
    case 'SEND_UDP':
      sendUDP(data, port);
      break;
      
    case 'CLOSE_SOCKET':
      closeSocket(port);
      break;
      
    default:
      port.postMessage({ success: false, error: 'Unknown message type' });
  }
});

async function createUDPSocket(port) {
  try {
    if (typeof UDPSocket === 'undefined') {
      port.postMessage({ success: false, error: 'UDPSocket not available' });
      return;
    }
    
    udpSocket = new UDPSocket({ localAddress: '0.0.0.0' });
    
    const { localAddress, localPort } = await udpSocket.opened;
    
    console.log(`[SW] UDP socket opened at ${localAddress}:${localPort}`);
    
    port.postMessage({
      success: true,
      localAddress,
      localPort
    });
    
  } catch (error) {
    console.error('[SW] Failed to create socket:', error);
    port.postMessage({ success: false, error: error.message });
  }
}

async function sendUDP(data, port) {
  try {
    if (!udpSocket) {
      port.postMessage({ success: false, error: 'Socket not created' });
      return;
    }
    
    const writer = udpSocket.writable.getWriter();
    await writer.write({
      data: data.buffer,
      remoteAddress: data.remoteAddress,
      remotePort: data.remotePort
    });
    writer.releaseLock();
    
    port.postMessage({ success: true });
    
  } catch (error) {
    console.error('[SW] Failed to send UDP:', error);
    port.postMessage({ success: false, error: error.message });
  }
}

async function closeSocket(port) {
  try {
    if (udpSocket) {
      await udpSocket.close();
      udpSocket = null;
    }
    port.postMessage({ success: true });
  } catch (error) {
    console.error('[SW] Failed to close socket:', error);
    port.postMessage({ success: false, error: error.message });
  }
}

console.log('[SW] Service Worker ready');
