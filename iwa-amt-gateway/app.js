// app.js
// Main application logic for IWA AMT Gateway using Direct Sockets API

import { parseAMTUrl, validateAMTUrl } from './amt-url-parser.js';
import { RELAY_STATE, MSG_TYPE } from './constants.js';
import { MPEGTSPlayer } from './mpegts-player.js';
import { PacketBuffer } from './packet-buffer.js';
import { parsePacketMetadata, extractTSPayload } from './packet-parser.js';
import { initUI, getConnectedRelays, getActiveGroups, updateRelayStats, updateGroupStats, updateRelayState, updateStatsUI } from './app-ui.js';

// Global state
let wasmReady = false;
let go = null;
let wasmInstance = null;
let udpSockets = new Map(); // Map: relayId -> socketInfo (supports multiple relays)
let relays = {};
let groups = {};
let stats = {
  packets: 0,
  bytes: 0,
  startTime: null
};
let totalPackets = 0;
let totalBytes = 0;

// Service Worker communication
let serviceWorker = null;
let messageChannel = null;

// Video player (using direct packet buffer for MPEG-TS)
let videoPlayer = null;
let packetBuffer = null;

// Current connection config (for stream URL)
let currentConnectionConfig = null;

// Register Service Worker
async function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    // Don't unregister - just register/update
    // Unregistering can cause issues with IWA context
    
    try {
      // Use ABSOLUTE path (not relative) for IWA compatibility
      // Relative paths (./file) don't work reliably in isolated-app:// context
      // Use full service-worker.js (not minimal) for Direct Sockets support
      let serviceWorkerUrl = '/service-worker.js';
      
      if (window.trustedTypes && window.trustedTypes.defaultPolicy) {
        serviceWorkerUrl = window.trustedTypes.defaultPolicy.createScriptURL('/service-worker.js');
      }
      
      const registration = await navigator.serviceWorker.register(serviceWorkerUrl, {
        scope: '/',
        updateViaCache: 'none'  // Force no caching
      });
      console.log('✓ Service Worker registered:', serviceWorkerUrl);
      
      // Check for updates and force reload if there's a waiting worker
      if (registration.waiting) {
        console.log('🔄 New service worker waiting, activating...');
        registration.waiting.postMessage({ type: 'SKIP_WAITING' });
        
        // Reload the page to use the new service worker
        navigator.serviceWorker.addEventListener('controllerchange', () => {
          console.log('🔄 Service worker updated, reloading page...');
          window.location.reload();
        });
      }
      
      // Listen for service worker updates
      registration.addEventListener('updatefound', () => {
        const newWorker = registration.installing;
        console.log('🔄 Service worker update found...');
        
        newWorker.addEventListener('statechange', () => {
          if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
            console.log('🔄 New service worker installed, activating...');
            newWorker.postMessage({ type: 'SKIP_WAITING' });
          }
        });
      });
      
      // Check for updates
      registration.update().catch(e => console.log('Update check:', e.message));
      
      // Force activate if there's a waiting service worker
      if (registration.waiting) {
        console.log('[App] Service worker waiting, forcing activation...');
        registration.waiting.postMessage({ type: 'SKIP_WAITING' });
        
        // Wait for it to become active
        await new Promise((resolve) => {
          navigator.serviceWorker.addEventListener('controllerchange', () => {
            console.log('[App] Controller changed, service worker now active');
            resolve();
          }, { once: true });
          
          // Timeout fallback
          setTimeout(resolve, 1000);
        });
      }
      
      // Wait for service worker to be ready
      await navigator.serviceWorker.ready;
      serviceWorker = registration.active || registration.installing || registration.waiting;
      
      // If still not active, force it
      if (!serviceWorker || serviceWorker.state !== 'activated') {
        console.log('[App] Service worker not active, waiting...');
        
        // If installing, wait for it
        if (registration.installing) {
          await new Promise((resolve) => {
            registration.installing.addEventListener('statechange', function handler(e) {
              if (e.target.state === 'activated') {
                console.log('[App] Service worker activated');
                resolve();
              }
            });
            setTimeout(resolve, 3000);  // Timeout after 3s
          });
        }
        
        serviceWorker = registration.active;
      }
      
      console.log('✓ Service Worker active');
      
      // Listen for messages from service worker
      navigator.serviceWorker.addEventListener('message', handleServiceWorkerMessage);
      
      return true;
    } catch (error) {
      console.error('Service Worker registration failed:', error);
      console.error('Error details:', {
        name: error.name,
        message: error.message,
        stack: error.stack
      });
      // Try to help diagnose the issue
      console.log('Attempting to fetch service worker file directly...');
      try {
        const response = await fetch('/service-worker.js');
        if (response.ok) {
          const contentType = response.headers.get('content-type');
          console.log('✓ Service worker file exists');
          console.log('  Content-Type:', contentType);
          console.log('  Status:', response.status);
          console.log('  Size:', (await response.text()).length, 'bytes');
        } else {
          console.error('✗ Service worker file returned status:', response.status);
        }
      } catch (fetchError) {
        console.error('✗ Could not fetch service worker file:', fetchError);
      }
      return false;
    }
  }
  console.warn('Service Worker API not available');
  return false;
}

// Send message to service worker
async function sendToServiceWorker(type, data = {}) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    
    channel.port1.onmessage = (event) => {
      if (event.data.success) {
        resolve(event.data);
      } else {
        reject(new Error(event.data.error || 'Unknown error'));
      }
    };
    
    serviceWorker.postMessage({ type, data }, [channel.port2]);
  });
}

// Handle messages from service worker
function handleServiceWorkerMessage(event) {
  const { type } = event.data;
  const msgData = event.data;  // Keep the whole message object
  
  switch (type) {
    case 'SOCKET_CREATED':
      // msgData now has a 'data' property containing localAddress, localPort, and relayId
      const socketInfo = msgData.data || msgData;
      const relayId = socketInfo.relayId || 'default';
      console.log(`✓ Socket created for relay ${relayId} at ${socketInfo.localAddress}:${socketInfo.localPort}`);
      
      // CRITICAL: Store socket info per relay so we don't create duplicates!
      udpSockets.set(relayId, socketInfo);
      
      if (globalThis._goUDPOnLocalAddr) {
        globalThis._goUDPOnLocalAddr(socketInfo.localAddress, socketInfo.localPort);
      }
      break;
      
    case 'UDP_PACKET':
      // Declare variables at case scope so they're accessible throughout
      const dataArray = msgData.data || [];
      const uint8Data = new Uint8Array(dataArray);
      const remoteAddr = msgData.remoteAddress || '0.0.0.0';
      const remotePort = msgData.remotePort || 0;
      const packetSize = msgData.size || dataArray.length;
      
      // Forward to WASM
      if (globalThis._goUDPOnReceive && uint8Data.length > 0) {
        globalThis._goUDPOnReceive(uint8Data, remoteAddr, remotePort);
      }
      
      // Update per-relay statistics (automatically adds relay if not found)
      updateRelayStats(remoteAddr, remotePort, packetSize);
      
      // Update global statistics
      stats.packets++;
      stats.bytes += packetSize;
      
      if (!stats.startTime) {
        stats.startTime = Date.now();
      }
      
      // CRITICAL: Only feed packets from ACTIVE stream to MediaSource
      // This prevents choppy playback from mixed streams
      if (packetBuffer && uint8Data.length > 0) {
        // Parse (S,G) from packet to identify which stream it belongs to
        const metadata = parsePacketMetadata(uint8Data);
        if (metadata.sourceIP && metadata.groupIP) {
          const packetKey = `${metadata.sourceIP}@${metadata.groupIP}:${metadata.port}`;
          
          // Debug: Log packet filtering (every 100 packets)
          if (stats.packets % 100 === 1) {
            console.log(`[App] Packet filter: parsed=${packetKey}, active=${window.activeGroupKey}, match=${packetKey === window.activeGroupKey}`);
          }
          
          // Only append to MediaSource if this packet is from the active stream
          if (packetKey === window.activeGroupKey) {
            // CRITICAL: Extract TS payload from AMT encapsulation
            const tsPayload = extractTSPayload(uint8Data);
            if (tsPayload && tsPayload.length > 0) {
              // Debug: Log successful extraction (first few packets)
              if (stats.packets <= 5) {
                console.log(`[App] ✓ Extracted TS payload: ${uint8Data.length} → ${tsPayload.length} bytes, first byte: 0x${uint8Data[0].toString(16)} → 0x${tsPayload[0].toString(16)}`);
              }
              // CRITICAL FIX: Pass Uint8Array directly, NOT .buffer (which returns the ENTIRE underlying ArrayBuffer including headers!)
              // tsPayload is a subarray view, and calling .buffer would expose all the AMT/IP/UDP headers too
              packetBuffer.addPacket(tsPayload);
            } else {
              // Log extraction failures
              if (stats.packets <= 10 || stats.packets % 100 === 0) {
                console.warn(`[App] ⚠️ Failed to extract TS payload from packet (size: ${uint8Data.length}, first byte: 0x${uint8Data[0].toString(16)}, AMT type: ${uint8Data[0] & 0x0F})`);
              }
            }
          }
          // Silently drop packets from inactive streams (they're still counted in stats)
        } else {
          // If parsing fails, try extracting TS payload anyway (might be control packet or corrupted)
          const tsPayload = extractTSPayload(uint8Data);
          if (tsPayload && tsPayload.length > 0) {
            // CRITICAL FIX: Pass Uint8Array directly, NOT .buffer
            packetBuffer.addPacket(tsPayload);
          }
        }
      }
      
      // Note: Auto-play now handled by 'canplay' event listener on video element
      // No need for packet-count-based playback trigger
      
      // Update UI every 50 packets for better performance
      if (stats.packets % 50 === 0) {
        updateStatsUI(stats);
        if (stats.packets % 100 === 0) {
          console.log(`[App] Stats: ${stats.packets} packets, ${formatBytes(stats.bytes)}`);
        }
      }
      
      // Update relay state based on packet reception
      // Small packets (< 100 bytes) are usually AMT control packets
      // Large packets (> 100 bytes) are multicast data
      if (Object.keys(relays).length > 0 && dataArray.length > 100) {
        for (const relay of Object.values(relays)) {
          if (relay.state !== RELAY_STATE.ACTIVE) {
            relay.state = RELAY_STATE.ACTIVE;
            updateRelayList();
            console.log(`Relay ${relay.name} now ACTIVE (receiving data)`);
          }
        }
      }
      break;
  }
}

// Check if Direct Sockets API is available (in Service Worker)
async function checkDirectSocketsAPI() {
  try {
    const result = await sendToServiceWorker('CHECK_API');
    
    if (!result.available || !result.hasUDP) {
      document.getElementById('direct-sockets-warning').style.display = 'block';
      console.error('Direct Sockets API not available in Service Worker!');
      console.log('Flags enabled:',  result);
      console.log('Note: Direct Sockets only works in Service Workers, not main window');
      return false;
    }
    
    console.log('✓ Direct Sockets API available in Service Worker');
    return true;
  } catch (error) {
    console.error('Failed to check API:', error);
    return false;
  }
}

// Initialize WASM
async function initWASM() {
  console.log('Initializing WASM...');
  
  // Load Go WASM runtime
  const wasmScript = document.createElement('script');
  wasmScript.src = 'wasm_exec.js';
  await new Promise((resolve, reject) => {
    wasmScript.onload = resolve;
    wasmScript.onerror = reject;
    document.head.appendChild(wasmScript);
  });
  
  go = new Go();
  
  // Set up Go callbacks
  setupGoCallbacks();
  
  // Load WASM module
  const result = await WebAssembly.instantiateStreaming(
    fetch('amt-client.wasm'),
    go.importObject
  );
  
  wasmInstance = result.instance;
  
  // Run the Go program
  go.run(wasmInstance);
  
  console.log('✓ WASM initialized');
}

// Set up callbacks for Go to call
function setupGoCallbacks() {
  // Callback for Go to send UDP packets via Service Worker
  // NOTE: Cannot be async - Go WASM expects synchronous return of integer
  globalThis._goUDPSend = (socketId, data, destIP, destPort) => {
    try {
      // Convert to ArrayBuffer if needed
      const buffer = data.buffer ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) : data;
      
      // CRITICAL: Determine relayId from destination address
      // Format: relay-IP-PORT (e.g., "relay-162.250.137.254-2268")
      // NOTE: IP keeps dots, only port is separated by hyphen
      const relayId = `relay-${destIP}-${destPort}`;
      
      // Send via Service Worker with correct relayId (fire and forget - don't await)
      sendToServiceWorker('SEND_UDP', {
        buffer: buffer,
        remoteAddress: destIP,
        remotePort: destPort,
        relayId: relayId
      }).catch(error => {
        console.error('UDP send error (async):', error);
      });
      
      // Return immediately - Go WASM expects a number, not a Promise
      return 0; // Success (optimistic - actual send happens async)
    } catch (error) {
      console.error('UDP send error:', error);
      return -1;
    }
  };
  
  // Callback for Go to close UDP socket
  // NOTE: Cannot be async - Go WASM expects synchronous execution
  globalThis._goUDPClose = (socketId) => {
    try {
      // Send close request (fire and forget)
      sendToServiceWorker('CLOSE_SOCKET').catch(error => {
        console.error('Socket close error (async):', error);
      });
      console.log('Socket close requested');
    } catch (error) {
      console.error('Socket close error:', error);
    }
  };
  
  // Called when WASM is ready
  globalThis._onAMTClientReady = () => {
    wasmReady = true;
    console.log('✓ AMT Client ready');
  };
}

// Create UDP socket via Service Worker (one per relay)
async function createUDPSocket(relayId = 'default') {
  try {
    console.log(`Creating UDP socket for relay ${relayId} via Service Worker...`);
    
    // Request Service Worker to create socket for this specific relay
    await sendToServiceWorker('CREATE_SOCKET', { relayId });
    
    // Start receiving packets for this relay
    await sendToServiceWorker('START_RECEIVE', { relayId });
    
    console.log(`✓ UDP socket created and receiving for relay ${relayId}`);
    
    return true;
  } catch (error) {
    console.error(`Failed to create UDP socket for relay ${relayId}:`, error);
    throw error;
  }
}

// Update statistics UI (now handled by app-ui.js)

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Handle connect button
async function handleConnect() {
  const amtUrl = document.getElementById('amt-url').value.trim();
  const relayName = document.getElementById('relay-name').value.trim();
  
  if (!validateAMTUrl(amtUrl)) {
    alert('Invalid AMT URL format');
    return;
  }
  
  try {
    const parsed = parseAMTUrl(amtUrl);
    const finalRelayName = relayName || `relay-${parsed.relayIP.replace(/\./g, '-')}`;
    
    // Store connection config for stream URL
    currentConnectionConfig = {
      source: parsed.source,
      group: parsed.group,
      mediaPort: parsed.mediaPort,
      relayIP: parsed.relayIP,
      relayPort: parsed.relayPort
    };
    
    console.log('Connecting to:', parsed);
    
    // Show loading
    const connectBtn = document.getElementById('connect-btn');
    connectBtn.textContent = 'Connecting...';
    connectBtn.disabled = true;
    
    // Create socket (via Service Worker)
    await createUDPSocket();
    
    // Connect via WASM
    if (globalThis.amtClient) {
      await globalThis.amtClient.connectToRelay(
        finalRelayName,
        parsed.relayIP,
        parsed.relayPort,
        (state) => {
          console.log(`Relay state: ${state}`);
          if (relays[finalRelayName]) {
            relays[finalRelayName].state = state;
          }
        }
      );
      
      // Join group and feed packets to video player
      await globalThis.amtClient.join(
        finalRelayName,
        parsed.source,
        parsed.group,
        parsed.mediaPort,
        (payload, metadata) => {
          // Packets are forwarded to Service Worker for output servers
          // Video player will load from TCP server URL (see UDP_PACKET handler)
          
          // Update stats periodically
          totalPackets++;
          totalBytes += metadata.size;
          if (totalPackets % 50 === 0) {
            updateStatsUI();
            
            // Mark relay as ACTIVE once we're receiving multicast data
            if (metadata.size > 100 && relays[finalRelayName]) {
              relays[finalRelayName].state = RELAY_STATE.ACTIVE;
              updateRelayList();
            }
          }
        }
      );
      
      // Update relays
      relays[finalRelayName] = {
        name: finalRelayName,
        ip: parsed.relayIP,
        port: parsed.relayPort,
        state: RELAY_STATE.ACTIVE,
        groups: [{
          source: parsed.source,
          group: parsed.group,
          port: parsed.mediaPort
        }]
      };
      
      updateRelayList();
      
      connectBtn.textContent = 'Connect & Join';
      connectBtn.disabled = false;
      
      console.log(`✓ Connected to ${finalRelayName}`);
      alert(`Connected successfully!\nJoined ${parsed.source}@${parsed.group}:${parsed.mediaPort}`);
      
    } else {
      throw new Error('WASM not ready');
    }
  } catch (error) {
    console.error('Connection error:', error);
    alert(`Failed to connect: ${error.message}`);
    
    document.getElementById('connect-btn').textContent = 'Connect & Join';
    document.getElementById('connect-btn').disabled = false;
  }
}

// Handle disconnect all
async function handleDisconnectAll() {
  if (!confirm('Disconnect from all relays?')) {
    return;
  }
  
  // Close socket via Service Worker
  try {
    await sendToServiceWorker('CLOSE_SOCKET');
  } catch (error) {
    console.error('Error closing socket:', error);
  }
  
  relays = {};
  groups = {};
  stats = { packets: 0, bytes: 0, startTime: null };
  
  updateRelayList();
  updateStatsUI();
  
  console.log('Disconnected from all relays');
}

// Update relay list UI
function updateRelayList() {
  const relayList = document.getElementById('relay-list');
  
  if (Object.keys(relays).length === 0) {
    relayList.innerHTML = '<p class="empty-state">No active relays</p>';
    return;
  }
  
  relayList.innerHTML = '';
  
  for (const [name, relay] of Object.entries(relays)) {
    const div = document.createElement('div');
    div.className = 'relay-item';
    div.innerHTML = `
      <h3>
        ${name}
        <span class="status ${relay.state.toLowerCase()}">${relay.state}</span>
      </h3>
      <p>Address: ${relay.ip}:${relay.port}</p>
      <p>Groups: ${relay.groups.length}</p>
    `;
    relayList.appendChild(div);
  }
  
  // Update group list too
  updateGroupList();
}

// Update group list UI
function updateGroupList() {
  const groupList = document.getElementById('group-list');
  
  const allGroups = [];
  for (const relay of Object.values(relays)) {
    for (const group of relay.groups) {
      allGroups.push({ ...group, relayName: relay.name });
    }
  }
  
  if (allGroups.length === 0) {
    groupList.innerHTML = '<p class="empty-state">No subscribed groups</p>';
    return;
  }
  
  groupList.innerHTML = '';
  
  for (const group of allGroups) {
    const div = document.createElement('div');
    div.className = 'group-item';
    div.innerHTML = `
      <h3>${group.source}@${group.group}:${group.port}</h3>
      <p>Via: ${group.relayName}</p>
    `;
    groupList.appendChild(div);
  }
}

// Initialize app
async function init() {
  console.log('Initializing Blockcast AMT Gateway (IWA)...');
  
  // Register Service Worker first (required for Direct Sockets)
  const swRegistered = await registerServiceWorker();
  if (!swRegistered) {
    console.error('Failed to register Service Worker');
    return;
  }
  
  // Check Direct Sockets availability in Service Worker
  const hasDirectSockets = await checkDirectSocketsAPI();
  if (!hasDirectSockets) {
    return;
  }
  
  // Initialize WASM
  await initWASM();
  
  // Initialize video player with direct packet buffer
  try {
    const videoElement = document.getElementById('video-player');
    if (videoElement) {
      // Initialize PacketBuffer for direct MPEG-TS streaming (no server needed!)
      packetBuffer = new PacketBuffer();
      packetBuffer.init(videoElement);
      
      // Periodically trim old buffer data (every 5 seconds)
      setInterval(() => {
        if (packetBuffer) {
          packetBuffer.trimBuffer();
        }
      }, 5000);
      
      // Keep MPEGTSPlayer for UI controls
      videoPlayer = new MPEGTSPlayer(videoElement);
      await videoPlayer.init();
      
      // Auto-play when video is ready
      videoElement.addEventListener('canplay', () => {
        console.log('[App] ✅ Video ready to play (readyState=' + videoElement.readyState + ')');
        if (videoElement.paused) {
          videoElement.play().then(() => {
            console.log('[App] ✅ Video playback started');
            document.getElementById('player-status').textContent = '▶️ Playing (Direct Streaming)';
          }).catch(err => {
            console.error('[App] Playback error:', err);
            document.getElementById('player-status').textContent = '⚠️ Click video to play';
          });
        }
      }, { once: false });  // Allow multiple triggers for stream switching
      
      videoElement.addEventListener('playing', () => {
        console.log('[App] ✅ Video is now playing');
        document.getElementById('player-status').textContent = '▶️ Playing (Direct Streaming)';
      });
      
      videoElement.addEventListener('waiting', () => {
        console.log('[App] ⏳ Video buffering...');
        document.getElementById('player-status').textContent = '⏳ Buffering...';
      });
      
      videoElement.addEventListener('error', (e) => {
        console.error('[App] Video error:', e, videoElement.error);
        document.getElementById('player-status').textContent = '❌ Playback error: ' + (videoElement.error?.message || 'Unknown');
      });
      
      // Video controls removed from UI - using HTML5 native controls
      console.log('[App] ✓ Video player initialized with auto-play on canplay');
    }
  } catch (error) {
    console.warn('Video player initialization failed:', error);
  }
  
  // Force restart button - unregisters service worker and reloads
  document.getElementById('force-restart-btn').addEventListener('click', async () => {
    console.log('🔄 Force restart requested...');
    
    if ('serviceWorker' in navigator) {
      const registration = await navigator.serviceWorker.getRegistration();
      if (registration) {
        console.log('🔄 Unregistering service worker...');
        await registration.unregister();
        console.log('✓ Service worker unregistered');
      }
    }
    
    // Clear all caches
    if ('caches' in window) {
      const cacheNames = await caches.keys();
      await Promise.all(cacheNames.map(name => caches.delete(name)));
      console.log('✓ Caches cleared');
    }
    
    console.log('🔄 Reloading page...');
    window.location.reload();
  });
  
  // Initialize UI with preloaded streams
  initUI();
  
  // Listen for UI events
  document.addEventListener('group-join', async (e) => {
    const { relay, group } = e.detail;
    console.log(`[App] Joining group: ${group.name} via ${relay.name}`);
    
    // Set as active group
    const groupKey = `${group.source}@${group.group}:${group.port}`;
    window.activeGroupKey = groupKey;
    
    // CRITICAL: Create ONE socket PER RELAY (not per stream)
    // Multiple streams on the same relay share the same socket
    // Different relays use different sockets
    const relayId = relay.id;
    if (!udpSockets.has(relayId)) {
      console.log(`[App] Creating UDP socket for relay ${relayId}...`);
      await createUDPSocket(relayId);
    } else {
      const socketInfo = udpSockets.get(relayId);
      console.log(`[App] ✓ Reusing socket for relay ${relayId} (port ${socketInfo.localPort})`);
    }
    
    // Connect to relay and join group
    if (globalThis.amtClient) {
      // Connect to relay (WASM handles duplicate connections)
      console.log(`[App] Ensuring connection to relay ${relay.name}...`);
      await globalThis.amtClient.connectToRelay(
        relay.id,
        relay.address,
        relay.port,
        (state) => {
          console.log(`[App] Relay ${relay.name} state: ${state}`);
        }
      );
      
      // Join group
      await globalThis.amtClient.join(
        relay.id,
        group.source,
        group.group,
        group.port,
        (payload, metadata) => {
          // Update per-group stats using the ACTUAL (S,G) from the packet metadata
          // This ensures we only count packets for THIS specific stream
          if (metadata && metadata.sourceIP && metadata.groupIP && metadata.port) {
            updateGroupStats(metadata.sourceIP, metadata.groupIP, metadata.port, metadata.size);
          }
          
          totalPackets++;
          totalBytes += metadata.size;
          if (totalPackets % 50 === 0) {
            updateStatsUI();
          }
        }
      );
      
      // Store current connection for video playback
      currentConnectionConfig = {
        source: group.source,
        group: group.group,
        mediaPort: group.port
      };
      
      console.log(`[App] ✅ Joined group successfully`);
    }
  });
  
  document.addEventListener('group-leave', async (e) => {
    const { group, groupKey } = e.detail;
    console.log(`[App] Leaving group: ${groupKey || group.name}`);
    
    // Note: The actual WASM leave() call is handled by app-ui.js window.leaveGroup()
    // This event is just for cleanup
    
    // Reset video playback
    if (packetBuffer) {
      packetBuffer.clear();
    }
    if (videoPlayer) {
      videoPlayer.stop();
    }
    
    document.getElementById('player-status').textContent = '⏹️ Stopped';
  });
  
  document.addEventListener('relay-disconnect', async (e) => {
    const { relayId } = e.detail;
    console.log(`[App] Disconnecting relay: ${relayId}`);
    
    if (globalThis.amtClient) {
      await globalThis.amtClient.disconnect(relayId);
    }
  });
  
  document.addEventListener('playback-refresh', async (e) => {
    const { group } = e.detail;
    console.log(`[App] Refreshing playback for: ${group.name}`);
    
    // Clear and restart video buffer
    if (packetBuffer) {
      packetBuffer.clear();
      stats.packets = 0;
      stats.bytes = 0;
      stats.startTime = null;
    }
    
    const videoElement = document.getElementById('video-player');
    if (videoElement && videoElement.paused) {
      videoElement.play().catch(err => {
        console.error('[App] Playback error:', err);
      });
    }
    
    document.getElementById('player-status').textContent = '🔄 Refreshing...';
  });
  
  document.addEventListener('group-switch', async (e) => {
    const { groupKey, group } = e.detail;
    console.log(`[App] Switching to group: ${groupKey}`);
    
    // This group is already joined, just refresh playback
    if (packetBuffer) {
      packetBuffer.clear();
      stats.packets = 0;
      stats.bytes = 0;
      stats.startTime = null;
      console.log('[App] ✓ Switched to group, playback refreshed');
    }
    
    // Video will auto-start playing from this group's packets
    const videoElement = document.getElementById('video-player');
    if (videoElement && videoElement.paused) {
      videoElement.play().catch(err => {
        console.error('[App] Playback error:', err);
      });
    }
    
    document.getElementById('player-status').textContent = '▶️ Switched Feed';
  });
  
  console.log('✓ App initialized and ready');
}

// Start initialization when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

