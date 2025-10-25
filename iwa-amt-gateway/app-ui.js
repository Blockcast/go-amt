/**
 * UI Management for IWA AMT Gateway
 * Handles all UI updates and user interactions
 */

import { DEFAULT_RELAYS, PRELOADED_STREAMS, getRelayById } from './stream-config.js';

// UI State
let connectedRelays = new Map();  // id -> {address, port, name, socket, stats: {packets, bytes, lastSeen}, state: 'connecting'|'active'|'inactive'}
let activeGroups = new Map();     // key -> {source, group, port, relay, stats: {packets, bytes, startTime}}
let selectedStream = null;
let globalStats = {
  packets: 0,
  bytes: 0,
  startTime: null
};

/**
 * Initialize UI with preloaded streams
 */
export function initUI() {
  populateStreamPicker();
  setupEventListeners();
  startHealthMonitoring();
  startServerStatusMonitoring();
  console.log('[UI] Initialized with', PRELOADED_STREAMS.length, 'preloaded streams');
}

/**
 * Start periodic health monitoring for relays
 */
function startHealthMonitoring() {
  // Check relay health every 5 seconds
  setInterval(() => {
    const now = Date.now();
    let stateChanged = false;
    
    for (const relay of connectedRelays.values()) {
      const oldState = relay.state;
      
      // Mark as inactive if no packets for 10 seconds
      if (relay.stats.lastSeen && now - relay.stats.lastSeen > 10000) {
        relay.state = 'inactive';
        if (oldState !== 'inactive') {
          console.log(`[UI] Relay ${relay.name} marked inactive (no packets for 10s)`);
          stateChanged = true;
        }
      }
      // Mark as connecting if last seen > 3 seconds but < 10 seconds
      else if (relay.stats.lastSeen && now - relay.stats.lastSeen > 3000) {
        relay.state = 'connecting';
        if (oldState !== 'connecting') {
          console.log(`[UI] Relay ${relay.name} marked connecting (slow packets)`);
          stateChanged = true;
        }
      }
    }
    
    if (stateChanged) {
      updateRelayList();
      updateRelayHierarchy();
      updateRelayStatusIndicator();
    }
  }, 5000); // Every 5 seconds
  
  console.log('[UI] ✓ Health monitoring started');
}

/**
 * Start periodic server status monitoring
 */
function startServerStatusMonitoring() {
  // Update server status every 3 seconds
  setInterval(async () => {
    await updateServerStatus();
  }, 3000);
  
  // Initial update
  updateServerStatus();
  
  console.log('[UI] ✓ Server status monitoring started');
}

/**
 * Update output server status display
 */
async function updateServerStatus() {
  try {
    // Request server status from Service Worker
    const registration = await navigator.serviceWorker.ready;
    const sw = registration.active;
    
    if (!sw) return;
    
    const status = await new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const timeout = setTimeout(() => reject(new Error('Timeout')), 2000);
      
      channel.port1.onmessage = (e) => {
        clearTimeout(timeout);
        resolve(e.data);
      };
      
      sw.postMessage({ type: 'GET_SERVER_STATUS' }, [channel.port2]);
    });
    
    displayServerStatus(status);
  } catch (error) {
    // Silently fail - server might not be started yet
  }
}

/**
 * Display output server status
 */
function displayServerStatus(status) {
  const container = document.getElementById('output-servers-list');
  if (!container) return;

  // Check if output servers are enabled
  if (status && status.serversEnabled && status.outputServers) {
    const servers = status.outputServers.servers || {};
    const serverNames = Object.keys(servers);
    
    if (serverNames.length === 0) {
      container.innerHTML = `
        <div style="color: #666; padding: 10px; font-size: 10px; line-height: 1.5;">
          <div style="margin-bottom: 6px;">
            <strong>🚀 Hybrid Mode</strong>
          </div>
          <div style="color: #999;">
            Direct Streaming + Output Servers (initializing...)
          </div>
        </div>
      `;
      return;
    }
    
    // Display each server's status
    let html = `
      <div style="color: #666; padding: 10px; font-size: 10px; line-height: 1.5;">
        <div style="margin-bottom: 8px;">
          <strong>🚀 Hybrid Mode: Direct Streaming + Output Servers</strong>
        </div>
    `;
    
    for (const [name, serverStatus] of Object.entries(servers)) {
      const enabled = serverStatus.enabled;
      const statusIcon = enabled ? '🟢' : '⚫';
      const statusText = enabled ? 'RUNNING' : 'STOPPED';
      const statusColor = enabled ? '#22c55e' : '#999';
      
      // Get port info if available
      let portInfo = '';
      if (name === 'udp' && serverStatus.controlPort) {
        portInfo = ` (port ${serverStatus.controlPort})`;
      } else if (name === 'websocket' && serverStatus.port) {
        portInfo = ` (port ${serverStatus.port})`;
      }
      
      // Get client count
      let clientInfo = '';
      if (serverStatus.activeConnections !== undefined) {
        clientInfo = ` • ${serverStatus.activeConnections} clients`;
      } else if (serverStatus.subscriptions !== undefined) {
        clientInfo = ` • ${serverStatus.subscriptions} subscriptions`;
      }
      
      html += `
        <div style="margin-bottom: 4px; padding: 4px; background: ${enabled ? '#f0fdf4' : '#f9fafb'}; border-left: 2px solid ${statusColor}; border-radius: 2px;">
          ${statusIcon} <strong>${name.toUpperCase()}</strong>${portInfo}
          <span style="color: ${statusColor}; font-weight: 600; margin-left: 4px;">${statusText}</span>
          ${clientInfo}
        </div>
      `;
    }
    
    html += `
        <div style="margin-top: 8px; padding-top: 6px; border-top: 1px solid #e5e7eb; font-size: 9px; color: #999;">
          Using Direct Sockets API (IWA-compatible)
        </div>
      </div>
    `;
    
    container.innerHTML = html;
  } else {
    // Fallback: direct streaming only
    container.innerHTML = `
      <div style="color: #666; padding: 10px; font-size: 10px; line-height: 1.5;">
        <div style="margin-bottom: 6px;">
          <strong>🚀 Direct Streaming Mode</strong>
        </div>
        <div style="color: #999;">
          Direct packet streaming (SW → PacketBuffer → MediaSource).<br>
          Output servers are initializing...
        </div>
      </div>
    `;
  }
}

/**
 * Populate stream picker dropdown
 */
function populateStreamPicker() {
  const picker = document.getElementById('stream-picker');
  picker.innerHTML = '<option value="">-- Choose a stream --</option>';
  
  PRELOADED_STREAMS.forEach((stream, index) => {
    const relay = getRelayById(stream.relay);
    const option = document.createElement('option');
    option.value = index;
    option.textContent = `${stream.name} [${relay.name}]`;
    picker.appendChild(option);
  });
}

/**
 * Setup all event listeners
 */
function setupEventListeners() {
  // Stream picker - auto-fills inputs
  document.getElementById('stream-picker').addEventListener('change', (e) => {
    const index = e.target.value;
    if (index === '') {
      selectedStream = null;
      // Clear inputs
      document.getElementById('source-address').value = '';
      document.getElementById('group-address').value = '';
      document.getElementById('media-port').value = '';
      document.getElementById('active-relay-select').value = '';
    } else {
      selectedStream = PRELOADED_STREAMS[parseInt(index)];
      
      // Auto-fill inputs from selected stream
      const relay = getRelayById(selectedStream.relay);
      document.getElementById('source-address').value = selectedStream.source;
      document.getElementById('group-address').value = selectedStream.group;
      document.getElementById('media-port').value = selectedStream.port;
      
      // Select matching relay in dropdown (or add it if not present)
      const relayId = `relay-${relay.address}-${relay.port}`;
      const relaySelect = document.getElementById('active-relay-select');
      
      // Check if relay exists in dropdown
      let relayOption = Array.from(relaySelect.options).find(opt => opt.value === relayId);
      
      if (!relayOption) {
        // Auto-add relay if not in list
        connectedRelays.set(relayId, {
          id: relayId,
          address: relay.address,
          port: relay.port,
          name: relay.name,
          socket: null,
          state: 'connecting',
          stats: { packets: 0, bytes: 0, lastSeen: null }
        });
        updateRelayList();
        updateRelayHierarchy();
      }
      
      relaySelect.value = relayId;
      
      console.log('[UI] Auto-filled:', {
        stream: selectedStream.name,
        relay: relay.name,
        source: selectedStream.source,
        group: selectedStream.group,
        port: selectedStream.port
      });
    }
  });
  
  // Relay management
  document.getElementById('add-relay-btn').addEventListener('click', handleAddRelay);
  
  // Initialize hierarchy view
  updateRelayHierarchy();
  document.getElementById('disconnect-relay-btn').addEventListener('click', handleDisconnectRelay);
  document.getElementById('relay-list').addEventListener('change', handleRelaySelection);
  
  // Group management (join-group-btn is now the main "Join & Play" button)
  document.getElementById('join-group-btn').addEventListener('click', handleJoinGroup);
  document.getElementById('leave-group-btn').addEventListener('click', handleLeaveGroup);
  document.getElementById('refresh-playback-btn').addEventListener('click', handleRefreshPlayback);
  
  // Hidden for compatibility - group-list is now in hierarchy
  const groupList = document.getElementById('group-list');
  if (groupList) {
    groupList.addEventListener('change', handleGroupSelection);
  }
}

/**
 * Add a relay
 */
async function handleAddRelay() {
  const addressField = document.getElementById('relay-address-add') || document.getElementById('relay-address');
  const nameField = document.getElementById('relay-name-add') || document.getElementById('relay-name');
  const address = addressField.value.trim();
  const name = nameField.value.trim() || address;
  
  if (!address) {
    alert('Please enter a relay address');
    return;
  }
  
  const [ip, portStr] = address.split(':');
  const port = portStr ? parseInt(portStr) : 2268; // Default AMT port
  
  const id = `relay-${ip}-${port}`;
  
  if (connectedRelays.has(id)) {
    alert('Already connected to this relay');
    return;
  }
  
  console.log(`[UI] Adding relay: ${name} (${ip}:${port})`);
  
  // Add to connected relays with stats tracking
  connectedRelays.set(id, {
    id,
    address: ip,
    port,
    name,
    socket: null, // Will be created when joining a group
    state: 'connecting',
    stats: {
      packets: 0,
      bytes: 0,
      lastSeen: null
    }
  });
  
  updateRelayList();
  updateRelayHierarchy();
  updateRelayStatusIndicator();
  
  // Clear inputs
  if (nameField) nameField.value = '';
}

/**
 * Disconnect from selected relay
 */
async function handleDisconnectRelay() {
  const select = document.getElementById('relay-list');
  const selectedId = select.value;
  
  if (!selectedId || selectedId === 'none') return;
  
  if (!confirm(`Disconnect from relay ${connectedRelays.get(selectedId).name}?`)) {
    return;
  }
  
  console.log(`[UI] Disconnecting relay:`, selectedId);
  
  // Remove all groups using this relay
  for (const [key, group] of activeGroups.entries()) {
    if (group.relayId === selectedId) {
      activeGroups.delete(key);
    }
  }
  
  // Emit disconnect event
  const event = new CustomEvent('relay-disconnect', { detail: { relayId: selectedId } });
  document.dispatchEvent(event);
  
  connectedRelays.delete(selectedId);
  updateRelayList();
  updateGroupList();
}

/**
 * Handle relay selection
 */
function handleRelaySelection() {
  const select = document.getElementById('relay-list');
  const hasSelection = select.value && select.value !== 'none';
  document.getElementById('disconnect-relay-btn').disabled = !hasSelection;
}

// handleLoadStream removed - stream selection now just auto-fills inputs

/**
 * Join a group manually
 */
async function handleJoinGroup() {
  const source = document.getElementById('source-address').value.trim();
  const group = document.getElementById('group-address').value.trim();
  const port = document.getElementById('media-port').value.trim();
  
  if (!source || !group || !port) {
    alert('Please fill in all group fields');
    return;
  }
  
  // Get selected relay from dropdown
  const relaySelect = document.getElementById('active-relay-select');
  const relayId = relaySelect.value;
  
  if (!relayId) {
    alert('Please select a relay first');
    return;
  }
  
  if (!connectedRelays.has(relayId)) {
    alert('Selected relay is not connected');
    return;
  }
  
  const groupKey = `${source}@${group}:${port}`;
  activeGroups.set(groupKey, {
    source,
    group,
    port: parseInt(port),
    relayId,
    name: groupKey,
    stats: {
      packets: 0,
      bytes: 0,
      startTime: Date.now()
    }
  });
  
  updateGroupList();
  updateRelayHierarchy();  // Immediately show in UI as "connecting"
  
  // Emit join event
  const event = new CustomEvent('group-join', {
    detail: {
      relay: connectedRelays.get(relayId),
      group: activeGroups.get(groupKey)
    }
  });
  document.dispatchEvent(event);
  
  // Clear inputs
  document.getElementById('source-address').value = '';
  document.getElementById('group-address').value = '';
  document.getElementById('media-port').value = '';
}

/**
 * Leave selected group
 */
async function handleLeaveGroup() {
  const select = document.getElementById('group-list');
  const selectedKey = select.value;
  
  if (!selectedKey || selectedKey === 'none') return;
  
  console.log(`[UI] Leaving group:`, selectedKey);
  
  // Emit leave event
  const event = new CustomEvent('group-leave', {
    detail: { group: activeGroups.get(selectedKey) }
  });
  document.dispatchEvent(event);
  
  activeGroups.delete(selectedKey);
  updateGroupList();
}

/**
 * Refresh playback for selected group
 */
async function handleRefreshPlayback() {
  const select = document.getElementById('group-list');
  const selectedKey = select.value;
  
  if (!selectedKey || selectedKey === 'none') return;
  
  console.log(`[UI] Refreshing playback for:`, selectedKey);
  
  // Emit refresh event
  const event = new CustomEvent('playback-refresh', {
    detail: { group: activeGroups.get(selectedKey) }
  });
  document.dispatchEvent(event);
}

/**
 * Handle group selection
 */
function handleGroupSelection() {
  const select = document.getElementById('group-list');
  const hasSelection = select.value && select.value !== 'none';
  document.getElementById('leave-group-btn').disabled = !hasSelection;
  document.getElementById('refresh-playback-btn').disabled = !hasSelection;
}

/**
 * Update relay list dropdown (and active relay selector) with stats
 */
function updateRelayList() {
  const select = document.getElementById('relay-list');
  const activeSelect = document.getElementById('active-relay-select');
  const relayListItems = document.getElementById('relay-list-items');
  
  // Update visual relay cards with stats
  if (relayListItems) {
    if (connectedRelays.size === 0) {
      relayListItems.innerHTML = '<div style="color: #999; font-size: 12px; padding: 8px;">No relays connected</div>';
      if (document.getElementById('disconnect-relay-btn')) {
        document.getElementById('disconnect-relay-btn').disabled = true;
      }
    } else {
      relayListItems.innerHTML = '';
      for (const [id, relay] of connectedRelays.entries()) {
        const card = document.createElement('div');
        card.className = 'relay-card';
        card.style.cssText = `
          padding: 8px;
          margin-bottom: 5px;
          border: 1px solid ${relay.state === 'active' ? '#4ade80' : relay.state === 'connecting' ? '#facc15' : '#d1d5db'};
          border-radius: 4px;
          font-size: 11px;
          background: ${relay.state === 'active' ? '#f0fdf4' : relay.state === 'connecting' ? '#fefce8' : '#f9fafb'};
        `;
        
        const statusIndicator = relay.state === 'active' ? '🟢' : relay.state === 'connecting' ? '🟡' : '⚫';
        const stateText = relay.state === 'active' ? 'ACTIVE' : relay.state === 'connecting' ? 'CONNECTING' : 'INACTIVE';
        
        const formatBytes = (bytes) => {
          if (bytes === 0) return '0 B';
          const k = 1024;
          const sizes = ['B', 'KB', 'MB', 'GB'];
          const i = Math.floor(Math.log(bytes) / Math.log(k));
          return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
        };
        
        card.innerHTML = `
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
            <strong style="font-size: 12px;">${statusIndicator} ${relay.name}</strong>
            <span style="font-size: 10px; color: #666;">${stateText}</span>
          </div>
          <div style="color: #666; font-size: 10px; margin-bottom: 4px;">
            ${relay.address}:${relay.port}
          </div>
          <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 4px; font-size: 10px; color: #444;">
            <div>📊 ${relay.stats.packets.toLocaleString()} pkts</div>
            <div>💾 ${formatBytes(relay.stats.bytes)}</div>
          </div>
          ${relay.stats.lastSeen ? `<div style="font-size: 9px; color: #999; margin-top: 2px;">Last seen: ${new Date(relay.stats.lastSeen).toLocaleTimeString()}</div>` : ''}
        `;
        
        relayListItems.appendChild(card);
      }
      if (document.getElementById('disconnect-relay-btn')) {
        document.getElementById('disconnect-relay-btn').disabled = false;
      }
    }
  }
  
  // Update hidden relay list (for management)
  if (select) {
    select.innerHTML = '';
    
    if (connectedRelays.size === 0) {
      const option = document.createElement('option');
      option.value = 'none';
      option.textContent = 'No relays connected';
      option.disabled = true;
      option.selected = true;
      select.appendChild(option);
    } else {
      for (const [id, relay] of connectedRelays.entries()) {
        const option = document.createElement('option');
        option.value = id;
        option.textContent = `${relay.name} (${relay.address}:${relay.port})`;
        select.appendChild(option);
      }
    }
  }
  
  // Update active relay selector (in top control bar)
  if (activeSelect) {
    activeSelect.innerHTML = '';
    
    if (connectedRelays.size === 0) {
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'No relay';
      activeSelect.appendChild(option);
    } else {
      for (const [id, relay] of connectedRelays.entries()) {
        const option = document.createElement('option');
        option.value = id;
        const statusIcon = relay.state === 'active' ? '🟢' : relay.state === 'connecting' ? '🟡' : '⚫';
        option.textContent = `${statusIcon} ${relay.name}`;
        option.selected = true; // Select the most recently added
        activeSelect.appendChild(option);
      }
    }
  }
}

/**
 * Update hierarchical relay view with groups and stats
 */
function updateRelayHierarchy() {
  const container = document.getElementById('relay-hierarchy');
  if (!container) return;
  
  if (connectedRelays.size === 0) {
    container.innerHTML = '<div style="color: #999; font-size: 13px; padding: 20px; text-align: center;">No active relays. Select a stream or add a relay to get started.</div>';
    return;
  }
  
  container.innerHTML = '';
  
  for (const [relayId, relay] of connectedRelays.entries()) {
    // Relay card
    const relayCard = document.createElement('div');
    relayCard.style.cssText = `
      margin-bottom: 12px;
      border: 2px solid ${relay.state === 'active' ? '#4ade80' : relay.state === 'connecting' ? '#facc15' : '#d1d5db'};
      border-radius: 8px;
      overflow: hidden;
      background: white;
    `;
    
    // Relay header
    const statusIcon = relay.state === 'active' ? '🟢' : relay.state === 'connecting' ? '🟡' : '⚫';
    const relayHeader = document.createElement('div');
    relayHeader.style.cssText = `
      background: ${relay.state === 'active' ? 'linear-gradient(135deg, #4ade80 0%, #22c55e 100%)' : relay.state === 'connecting' ? 'linear-gradient(135deg, #facc15 0%, #eab308 100%)' : 'linear-gradient(135deg, #d1d5db 0%, #9ca3af 100%)'};
      color: white;
      padding: 10px 12px;
      font-weight: 600;
      font-size: 13px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    `;
    relayHeader.innerHTML = `
      <div>${statusIcon} ${relay.name}</div>
      <div style="font-size: 11px; opacity: 0.9;">${relay.address}:${relay.port}</div>
    `;
    relayCard.appendChild(relayHeader);
    
    // Relay stats
    const formatBytes = (bytes) => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
    };
    
    const relayStats = document.createElement('div');
    relayStats.style.cssText = `
      padding: 8px 12px;
      background: #f9fafb;
      display: grid;
      grid-template-columns: 1fr 1fr 1fr;
      gap: 8px;
      font-size: 11px;
      border-bottom: 1px solid #e5e7eb;
    `;
    relayStats.innerHTML = `
      <div><strong>📊 ${relay.stats.packets.toLocaleString()}</strong><br><span style="color: #666;">packets</span></div>
      <div><strong>💾 ${formatBytes(relay.stats.bytes)}</strong><br><span style="color: #666;">data</span></div>
      <div><strong>${relay.stats.lastSeen ? new Date(relay.stats.lastSeen).toLocaleTimeString() : 'Never'}</strong><br><span style="color: #666;">last seen</span></div>
    `;
    relayCard.appendChild(relayStats);
    
    // Find groups for this relay
    const relayGroups = Array.from(activeGroups.entries()).filter(([, group]) => group.relayId === relayId);
    
    if (relayGroups.length > 0) {
      const groupsContainer = document.createElement('div');
      groupsContainer.style.cssText = 'padding: 8px 12px;';
      
      const groupsTitle = document.createElement('div');
      groupsTitle.style.cssText = 'font-size: 11px; color: #666; margin-bottom: 6px; font-weight: 600;';
      groupsTitle.textContent = `📺 Active Groups (${relayGroups.length})`;
      groupsContainer.appendChild(groupsTitle);
      
      relayGroups.forEach(([groupKey, group]) => {
        const isActive = groupKey === window.activeGroupKey; // Track active group
        const groupItem = document.createElement('div');
        groupItem.className = 'group-row';
        groupItem.dataset.groupKey = groupKey;
        groupItem.style.cssText = `
          padding: 6px 8px;
          margin-bottom: 4px;
          background: ${isActive ? '#e0e7ff' : 'white'};
          border-left: 3px solid ${isActive ? '#4f46e5' : '#667eea'};
          border-radius: 3px;
          font-size: 11px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          cursor: pointer;
          transition: all 0.2s;
        `;
        // Format bytes helper
        const formatBytes = (bytes) => {
          if (bytes === 0) return '0 B';
          const k = 1024;
          const sizes = ['B', 'KB', 'MB', 'GB'];
          const i = Math.floor(Math.log(bytes) / Math.log(k));
          return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
        };
        
        // Calculate bitrate if we have stats
        let bitrateText = '';
        if (group.stats && group.stats.packets > 0 && group.stats.startTime) {
          const elapsed = (Date.now() - group.stats.startTime) / 1000; // seconds
          const bitrate = elapsed > 0 ? (group.stats.bytes * 8 / elapsed / 1000000).toFixed(2) : '0.00';
          bitrateText = `${bitrate} Mbps`;
        }
        
        groupItem.innerHTML = `
          <div style="flex: 1; pointer-events: none;">
            <strong>${isActive ? '▶️ ' : ''}${group.name || groupKey}</strong><br>
            <span style="color: #666; font-size: 10px;">${group.source}@${group.group}:${group.port}</span>
            ${group.stats && group.stats.packets > 0 ? `
              <div style="display: flex; gap: 8px; margin-top: 2px; font-size: 9px; color: #888;">
                <span>📊 ${group.stats.packets.toLocaleString()}</span>
                <span>💾 ${formatBytes(group.stats.bytes)}</span>
                ${bitrateText ? `<span>⚡ ${bitrateText}</span>` : ''}
              </div>
            ` : ''}
          </div>
          <button class="leave-group-btn" data-group-key="${groupKey}" style="
            background: #ef4444;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 10px;
            cursor: pointer;
          ">Leave</button>
        `;
        
        // Leave button - stop propagation so it doesn't trigger row click
        const leaveBtn = groupItem.querySelector('.leave-group-btn');
        leaveBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          window.leaveGroup(groupKey);
        });
        
        // Click row to switch video feed
        groupItem.addEventListener('click', () => {
          console.log(`[UI] Switching to group: ${groupKey}`);
          window.activeGroupKey = groupKey;
          
          // Dispatch event to refresh playback with this group
          const event = new CustomEvent('group-switch', { detail: { groupKey, group } });
          document.dispatchEvent(event);
          
          // Refresh hierarchy to show new active state
          updateRelayHierarchy();
        });
        
        // Hover effect
        groupItem.addEventListener('mouseenter', () => {
          if (!isActive) {
            groupItem.style.background = '#f3f4f6';
          }
        });
        groupItem.addEventListener('mouseleave', () => {
          if (!isActive) {
            groupItem.style.background = 'white';
          }
        });
        
        groupsContainer.appendChild(groupItem);
      });
      
      relayCard.appendChild(groupsContainer);
    } else {
      const noGroups = document.createElement('div');
      noGroups.style.cssText = 'padding: 8px 12px; font-size: 11px; color: #999; font-style: italic;';
      noGroups.textContent = 'No groups joined on this relay';
      relayCard.appendChild(noGroups);
    }
    
    container.appendChild(relayCard);
  }
}

// Global function for leave group button
window.leaveGroup = async function(groupKey) {
  const group = activeGroups.get(groupKey);
  if (!group) {
    console.warn(`[UI] Group ${groupKey} not found`);
    return;
  }
  
  console.log(`[UI] Leaving group: ${groupKey}`);
  
  // Call WASM leaveGroup with proper arguments
  if (globalThis.amtClient && globalThis.amtClient.leave) {
    const relay = connectedRelays.get(group.relayId);
    if (relay) {
      const relayName = relay.id;
      const sourceIP = group.source || '*';
      const groupIP = group.group;
      
      console.log(`[UI] Calling WASM leave(${relayName}, ${sourceIP}, ${groupIP})`);
      
      try {
        await globalThis.amtClient.leave(relayName, sourceIP, groupIP);
        console.log(`[UI] ✓ Successfully left group ${groupKey}`);
      } catch (err) {
        // AMT protocol may require waiting for Query before leaving
        // This is expected if leaving immediately after joining
        if (err.toString().includes('must receive Membership Query')) {
          console.log(`[UI] ⚠️ Leave deferred (waiting for protocol handshake)`);
          // Don't fail - just continue with cleanup
        } else {
          console.error(`[UI] Failed to leave group:`, err);
          // Don't return - still do cleanup
        }
      }
    }
  }
  
  // Dispatch event for app.js to handle cleanup
  const event = new CustomEvent('group-leave', { detail: { groupKey, group } });
  document.dispatchEvent(event);
  
  // Remove from active groups
  activeGroups.delete(groupKey);
  updateGroupList();
  updateRelayHierarchy();
};

/**
 * Update group list dropdown
 */
function updateGroupList() {
  const select = document.getElementById('group-list');
  select.innerHTML = '';
  
  if (activeGroups.size === 0) {
    const option = document.createElement('option');
    option.value = 'none';
    option.textContent = 'No groups joined';
    option.disabled = true;
    option.selected = true;
    select.appendChild(option);
    document.getElementById('leave-group-btn').disabled = true;
    document.getElementById('refresh-playback-btn').disabled = true;
    return;
  }
  
  for (const [key, group] of activeGroups.entries()) {
    const option = document.createElement('option');
    option.value = key;
    option.textContent = `${group.name} (${group.source}@${group.group}:${group.port})`;
    select.appendChild(option);
  }
}

/**
 * Get connected relays
 */
export function getConnectedRelays() {
  return connectedRelays;
}

/**
 * Get active groups
 */
export function getActiveGroups() {
  return activeGroups;
}

/**
 * Update relay stats when a packet is received
 * @param {string} relayAddress - IP address of the relay
 * @param {number} relayPort - Port of the relay
 * @param {number} packetSize - Size of the packet in bytes
 */
/**
 * Update per-group stats for a specific (S,G) pair
 * Called from WASM join callback with packet metadata
 */
export function updateGroupStats(sourceIP, groupIP, groupPort, packetSize) {
  const groupKey = `${sourceIP}@${groupIP}:${groupPort}`;
  const group = activeGroups.get(groupKey);
  
  if (group) {
    group.stats.packets++;
    group.stats.bytes += packetSize;
  }
}

/**
 * Update relay stats when a packet is received
 * @param {string} relayAddress - IP address of the relay
 * @param {number} relayPort - Port of the relay
 * @param {number} packetSize - Size of the packet in bytes
 */
export function updateRelayStats(relayAddress, relayPort, packetSize) {
  const relayId = `relay-${relayAddress}-${relayPort}`;
  const relay = connectedRelays.get(relayId);
  
  if (relay) {
    relay.stats.packets++;
    relay.stats.bytes += packetSize;
    relay.stats.lastSeen = Date.now();
    
    // Mark relay as active if it was connecting
    if (relay.state === 'connecting') {
      relay.state = 'active';
      console.log(`[UI] Relay ${relay.name} is now ACTIVE`);
    }
    
    // Update global stats (total across all groups)
    globalStats.packets++;
    globalStats.bytes += packetSize;
    if (!globalStats.startTime) {
      globalStats.startTime = Date.now();
    }
    
    // Update UI less frequently (every 50 packets instead of 10 for better performance)
    if (relay.stats.packets % 50 === 0) {
      updateRelayList();
      updateRelayHierarchy();
    }
  } else {
    // Auto-add relay if not found
    console.log(`[UI] Auto-adding relay: ${relayAddress}:${relayPort}`);
    connectedRelays.set(relayId, {
      id: relayId,
      address: relayAddress,
      port: relayPort,
      name: `${relayAddress}:${relayPort}`,
      socket: null,
      state: 'active',
      stats: {
        packets: 1,
        bytes: packetSize,
        lastSeen: Date.now()
      }
    });
    updateRelayList();
    updateRelayHierarchy();
  }
}

/**
 * Update relay state
 * @param {string} relayAddress - IP address of the relay
 * @param {number} relayPort - Port of the relay
 * @param {string} state - 'connecting'|'active'|'inactive'
 */
export function updateRelayState(relayAddress, relayPort, state) {
  const relayId = `relay-${relayAddress}-${relayPort}`;
  const relay = connectedRelays.get(relayId);
  
  if (relay && relay.state !== state) {
    relay.state = state;
    console.log(`[UI] Relay ${relay.name} state: ${state}`);
    updateRelayList();
    updateRelayStatusIndicator();
  }
}

/**
 * Update top bar status indicator based on relay states
 */
function updateRelayStatusIndicator() {
  const indicator = document.getElementById('relay-status-indicator');
  if (!indicator) return;
  
  // Check if any relay is active
  let hasActiveRelay = false;
  let hasConnectingRelay = false;
  
  for (const relay of connectedRelays.values()) {
    if (relay.state === 'active') {
      hasActiveRelay = true;
      break;
    } else if (relay.state === 'connecting') {
      hasConnectingRelay = true;
    }
  }
  
  // Update indicator
  indicator.className = 'status-indicator';
  if (hasActiveRelay) {
    indicator.classList.add('status-connected');
    indicator.title = 'Connected to relay';
  } else if (hasConnectingRelay) {
    indicator.classList.add('status-connecting');
    indicator.title = 'Connecting to relay...';
  } else {
    indicator.classList.add('status-disconnected');
    indicator.title = 'No relay connected';
  }
}

/**
 * Update global stats display
 */
export function updateStatsUI(stats) {
  // ALWAYS use global stats (total across all streams) - ignore passed stats parameter
  // This ensures the right-side stats show cumulative totals
  const s = globalStats;
  
  const packetsEl = document.getElementById('packets-count');
  const bytesEl = document.getElementById('bytes-count');
  const throughputEl = document.getElementById('throughput');
  const timeEl = document.getElementById('connection-time');
  
  if (packetsEl) packetsEl.textContent = s.packets.toLocaleString();
  if (bytesEl) {
    const formatBytes = (bytes) => {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return (bytes / Math.pow(k, i)).toFixed(2) + ' ' + sizes[i];
    };
    bytesEl.textContent = formatBytes(s.bytes);
  }
  
  if (s.startTime && throughputEl && timeEl) {
    const elapsed = (Date.now() - s.startTime) / 1000;
    const rate = (s.bytes * 8) / elapsed / 1000000; // Mbps
    throughputEl.textContent = rate.toFixed(2) + ' Mbps';
    timeEl.textContent = Math.floor(elapsed) + 's';
  } else {
    if (throughputEl) throughputEl.textContent = '0 Mbps';
    if (timeEl) timeEl.textContent = '0s';
  }
}

