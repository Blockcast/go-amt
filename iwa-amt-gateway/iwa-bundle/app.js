// app.js
// Main application logic for IWA AMT Gateway using Direct Sockets API

import { parseAMTUrl, validateAMTUrl } from './amt-url-parser.js';
import { RELAY_STATE, MSG_TYPE } from './constants.js';

// Global state
let wasmReady = false;
let go = null;
let wasmInstance = null;
let udpSocket = null;
let relays = {};
let groups = {};
let stats = {
  packets: 0,
  bytes: 0,
  startTime: null
};

// Service Worker communication
let serviceWorker = null;
let messageChannel = null;

// Register Service Worker
async function registerServiceWorker() {
  if ('serviceWorker' in navigator) {
    try {
      // Pre-fetch service worker to ensure it's in the IWA bundle
      // This is needed for Dev Mode Proxy to include it
      try {
        const swResponse = await fetch('/service-worker-minimal.js');
        if (!swResponse.ok) {
          console.error('Service worker file not accessible:', swResponse.status);
        } else {
          console.log('✓ Service worker file accessible');
        }
      } catch (e) {
        console.error('Failed to pre-fetch service worker:', e);
      }
      
      // Register service worker - in isolated-app context, no Trusted Types needed
      const registration = await navigator.serviceWorker.register('/service-worker-minimal.js', {
        scope: '/'
      });
      console.log('✓ Service Worker registered', registration);
      
      // Wait for service worker to be ready
      await navigator.serviceWorker.ready;
      serviceWorker = registration.active || registration.installing || registration.waiting;
      
      if (!serviceWorker) {
        throw new Error('Service Worker not active after registration');
      }
      
      console.log('✓ Service Worker active');
      
      // Listen for messages from service worker
      navigator.serviceWorker.addEventListener('message', handleServiceWorkerMessage);
      
      return true;
    } catch (error) {
      console.error('Service Worker registration failed:', error);
      console.error('Error details:', error.name, error.message);
      return false;
    }
  }
  console.error('Service Worker not supported');
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
  const { type, data: msgData } = event.data;
  
  switch (type) {
    case 'SOCKET_CREATED':
      console.log(`✓ Socket created at ${msgData.localAddress}:${msgData.localPort}`);
      if (globalThis._goUDPOnLocalAddr) {
        globalThis._goUDPOnLocalAddr(msgData.localAddress, msgData.localPort);
      }
      break;
      
    case 'UDP_PACKET':
      // Forward to WASM
      if (globalThis._goUDPOnReceive) {
        const uint8Data = new Uint8Array(msgData.data);
        globalThis._goUDPOnReceive(uint8Data, msgData.remoteAddress, msgData.remotePort);
      }
      
      // Update statistics
      stats.packets++;
      stats.bytes += msgData.size;
      
      if (!stats.startTime) {
        stats.startTime = Date.now();
      }
      
      if (stats.packets % 30 === 0) {
        updateStatsUI();
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
  globalThis._goUDPSend = async (socketId, data, destIP, destPort) => {
    try {
      // Convert to ArrayBuffer if needed
      const buffer = data.buffer ? data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) : data;
      
      // Send via Service Worker
      await sendToServiceWorker('SEND_UDP', {
        buffer: buffer,
        remoteAddress: destIP,
        remotePort: destPort
      });
      
      return 0; // Success
    } catch (error) {
      console.error('UDP send error:', error);
      return -1;
    }
  };
  
  // Callback for Go to close UDP socket
  globalThis._goUDPClose = async (socketId) => {
    try {
      await sendToServiceWorker('CLOSE_SOCKET');
      console.log('Socket closed');
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

// Create UDP socket via Service Worker
async function createUDPSocket() {
  try {
    console.log('Creating UDP socket via Service Worker...');
    
    // Request Service Worker to create socket
    await sendToServiceWorker('CREATE_SOCKET');
    
    // Start receiving packets
    await sendToServiceWorker('START_RECEIVE');
    
    console.log('✓ UDP socket created and receiving');
    
    return true;
  } catch (error) {
    console.error('Failed to create UDP socket:', error);
    throw error;
  }
}

// Update statistics UI
function updateStatsUI() {
  document.getElementById('stat-packets').textContent = stats.packets.toLocaleString();
  document.getElementById('stat-bytes').textContent = formatBytes(stats.bytes);
  
  if (stats.startTime) {
    const elapsed = (Date.now() - stats.startTime) / 1000;
    const rate = (stats.bytes * 8) / elapsed / 1000000; // Mbps
    document.getElementById('stat-rate').textContent = rate.toFixed(2) + ' Mbps';
  }
  
  document.getElementById('stat-streams').textContent = Object.keys(relays).length;
}

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
      
      // Join group
      await globalThis.amtClient.join(
        finalRelayName,
        parsed.source,
        parsed.group,
        parsed.mediaPort,
        (payload, metadata) => {
          // Packet received - already handled in startPacketReception
          console.log(`Packet: ${metadata.size} bytes from ${metadata.sourceIP}@${metadata.groupIP}:${metadata.groupPort}`);
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
  
  // Set up event listeners
  document.getElementById('connect-btn').addEventListener('click', handleConnect);
  document.getElementById('disconnect-all-btn').addEventListener('click', handleDisconnectAll);
  
  console.log('✓ App initialized and ready');
}

// Start initialization when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

