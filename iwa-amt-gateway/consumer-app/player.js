/**
 * Blockcast AMT Stream Consumer
 * 
 * Connects to IWA Gateway output servers and plays MPEG-TS streams
 */

class StreamConsumer {
  constructor() {
    // Connection state
    this.connected = false;
    this.protocol = null;
    this.connection = null;
    this.player = null;
    
    // Stream info
    this.currentStream = {
      source: '*',
      group: '239.255.1.1',
      port: 5000
    };
    
    // Statistics
    this.stats = {
      bytesReceived: 0,
      packetsReceived: 0,
      connectionStartTime: null,
      droppedFrames: 0
    };
    
    // UI Elements
    this.elements = {
      protocol: document.getElementById('protocol'),
      gatewayHost: document.getElementById('gateway-host'),
      sourceIP: document.getElementById('source-ip'),
      groupIP: document.getElementById('group-ip'),
      groupPort: document.getElementById('group-port'),
      connectBtn: document.getElementById('connect-btn'),
      disconnectBtn: document.getElementById('disconnect-btn'),
      statusIndicator: document.getElementById('connection-status'),
      statusText: document.querySelector('#connection-status .status-text'),
      videoPlayer: document.getElementById('video-player'),
      playerOverlay: document.getElementById('player-overlay'),
      currentStream: document.getElementById('current-stream'),
      currentProtocol: document.getElementById('current-protocol'),
      currentBitrate: document.getElementById('current-bitrate'),
      droppedFrames: document.getElementById('dropped-frames'),
      bytesReceived: document.getElementById('bytes-received'),
      packetsReceived: document.getElementById('packets-received'),
      connectionTime: document.getElementById('connection-time'),
      bufferLevel: document.getElementById('buffer-level'),
      logContainer: document.getElementById('log-container'),
      clearLogsBtn: document.getElementById('clear-logs-btn')
    };
    
    this.init();
  }
  
  /**
   * Initialize consumer app
   */
  init() {
    this.log('info', 'Initializing consumer app...');
    
    // Check mpegts.js availability
    if (typeof mpegts === 'undefined') {
      this.log('error', 'mpegts.js not loaded! Cannot play MPEG-TS streams.');
      this.updateStatus('error', 'mpegts.js not loaded');
      return;
    }
    
    this.log('success', 'mpegts.js loaded successfully');
    
    // Setup event listeners
    this.setupEventListeners();
    
    // Start stats update timer
    setInterval(() => this.updateStats(), 1000);
    
    this.log('success', 'Consumer app ready!');
  }
  
  /**
   * Setup UI event listeners
   */
  setupEventListeners() {
    // Connect/Disconnect buttons
    this.elements.connectBtn.addEventListener('click', () => this.connect());
    this.elements.disconnectBtn.addEventListener('click', () => this.disconnect());
    
    // Channel preset buttons
    document.querySelectorAll('.channel-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const source = e.target.dataset.source;
        const group = e.target.dataset.group;
        const port = e.target.dataset.port;
        this.loadChannel(source, group, port);
      });
    });
    
    // Clear logs button
    this.elements.clearLogsBtn.addEventListener('click', () => this.clearLogs());
    
    // Video player events
    this.elements.videoPlayer.addEventListener('loadeddata', () => {
      this.log('success', 'Video loaded, ready to play');
      this.elements.playerOverlay.classList.add('hidden');
    });
    
    this.elements.videoPlayer.addEventListener('playing', () => {
      this.log('success', 'Video playback started');
    });
    
    this.elements.videoPlayer.addEventListener('pause', () => {
      this.log('info', 'Video playback paused');
    });
    
    this.elements.videoPlayer.addEventListener('error', (e) => {
      this.log('error', `Video error: ${e.message || 'Unknown error'}`);
    });
  }
  
  /**
   * Load channel preset
   */
  loadChannel(source, group, port) {
    this.elements.sourceIP.value = source;
    this.elements.groupIP.value = group;
    this.elements.groupPort.value = port;
    
    this.log('info', `Loaded channel: (${source}, ${group}:${port})`);
    
    // Auto-connect if already connected
    if (this.connected) {
      this.disconnect();
      setTimeout(() => this.connect(), 500);
    }
  }
  
  /**
   * Connect to stream
   */
  async connect() {
    if (this.connected) {
      this.log('warning', 'Already connected');
      return;
    }
    
    this.updateStatus('connecting', 'Connecting...');
    this.log('info', 'Connecting to stream...');
    
    // Get configuration
    const protocol = this.elements.protocol.value;
    const host = this.elements.gatewayHost.value;
    const source = this.elements.sourceIP.value || '*';
    const group = this.elements.groupIP.value;
    const port = parseInt(this.elements.groupPort.value);
    
    // Validate
    if (!group || !port) {
      this.log('error', 'Invalid stream configuration');
      this.updateStatus('error', 'Invalid configuration');
      return;
    }
    
    this.currentStream = { source, group, port };
    this.protocol = protocol;
    
    try {
      switch (protocol) {
        case 'tcp':
          await this.connectTCP(host, source, group, port);
          break;
        case 'websocket':
          await this.connectWebSocket(host, source, group, port);
          break;
        default:
          throw new Error(`Unsupported protocol: ${protocol}`);
      }
      
      this.connected = true;
      this.stats.connectionStartTime = Date.now();
      
      // Update UI
      this.updateStatus('connected', 'Connected');
      this.elements.connectBtn.disabled = true;
      this.elements.disconnectBtn.disabled = false;
      this.elements.currentStream.textContent = `(${source}, ${group}:${port})`;
      this.elements.currentProtocol.textContent = protocol.toUpperCase();
      
      this.log('success', `Connected via ${protocol.toUpperCase()}`);
      
    } catch (error) {
      this.log('error', `Connection failed: ${error.message}`);
      this.updateStatus('error', 'Connection failed');
      this.disconnect();
    }
  }
  
  /**
   * Connect via TCP/HTTP
   */
  async connectTCP(host, source, group, port) {
    this.log('info', `Connecting via TCP/HTTP to ${host}:5001...`);
    
    // Build URL
    const url = `http://${host}:5001/stream/${encodeURIComponent(source)}/${encodeURIComponent(group)}/${port}`;
    
    this.log('info', `Stream URL: ${url}`);
    
    // Create mpegts.js player
    if (mpegts.getFeatureList().mseLivePlayback) {
      this.log('success', 'MSE Live Playback supported');
      
      this.player = mpegts.createPlayer({
        type: 'mpegts',
        isLive: true,
        url: url
      }, {
        enableWorker: true,
        enableStashBuffer: false,
        stashInitialSize: 128,
        liveBufferLatencyChasing: true,
        liveBufferLatencyMaxLatency: 3,
        liveBufferLatencyMinRemain: 0.5
      });
      
      this.player.attachMediaElement(this.elements.videoPlayer);
      
      // Setup player event listeners
      this.player.on(mpegts.Events.ERROR, (errorType, errorDetail, errorInfo) => {
        this.log('error', `Player error: ${errorType} - ${errorDetail}`);
        console.error('Player error:', errorType, errorDetail, errorInfo);
      });
      
      this.player.on(mpegts.Events.LOADING_COMPLETE, () => {
        this.log('info', 'Loading complete');
      });
      
      this.player.on(mpegts.Events.STATISTICS_INFO, (stats) => {
        this.stats.bytesReceived = stats.totalBytes || 0;
        this.stats.droppedFrames = stats.droppedFrames || 0;
        this.elements.currentBitrate.textContent = this.formatBitrate(stats.speed || 0);
        this.elements.droppedFrames.textContent = this.stats.droppedFrames;
      });
      
      this.player.load();
      this.player.play().catch(err => {
        this.log('error', `Playback error: ${err.message}`);
      });
      
    } else {
      throw new Error('MSE Live Playback not supported in this browser');
    }
  }
  
  /**
   * Connect via WebSocket
   */
  async connectWebSocket(host, source, group, port) {
    this.log('info', `Connecting via WebSocket to ${host}:5002...`);
    
    // Create WebSocket connection
    const url = `ws://${host}:5002`;
    this.connection = new WebSocket(url);
    
    this.connection.binaryType = 'arraybuffer';
    
    // Setup WebSocket handlers
    this.connection.onopen = () => {
      this.log('success', 'WebSocket connected');
      
      // Send subscription message
      const subscription = {
        type: 'subscribe',
        source,
        group,
        port
      };
      
      this.connection.send(JSON.stringify(subscription));
      this.log('info', `Sent subscription: (${source}, ${group}:${port})`);
    };
    
    this.connection.onmessage = (event) => {
      if (typeof event.data === 'string') {
        // Text message (control)
        try {
          const message = JSON.parse(event.data);
          this.handleWebSocketControlMessage(message);
        } catch (err) {
          this.log('warning', 'Failed to parse WebSocket message');
        }
      } else {
        // Binary message (stream data)
        this.handleWebSocketData(event.data);
      }
    };
    
    this.connection.onerror = (error) => {
      this.log('error', `WebSocket error: ${error.message || 'Unknown'}`);
    };
    
    this.connection.onclose = () => {
      this.log('warning', 'WebSocket closed');
      if (this.connected) {
        this.disconnect();
      }
    };
    
    // Wait for connection
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('WebSocket connection timeout'));
      }, 10000);
      
      const checkConnection = () => {
        if (this.connection.readyState === WebSocket.OPEN) {
          clearTimeout(timeout);
          resolve();
        }
      };
      
      this.connection.addEventListener('open', checkConnection);
    });
  }
  
  /**
   * Handle WebSocket control message
   */
  handleWebSocketControlMessage(message) {
    this.log('info', `WS control: ${message.type}`);
    
    switch (message.type) {
      case 'subscribed':
        this.log('success', 'Subscription confirmed');
        break;
      case 'pong':
        // Heartbeat response
        break;
      default:
        this.log('info', `Unknown message type: ${message.type}`);
    }
  }
  
  /**
   * Handle WebSocket binary data
   */
  handleWebSocketData(data) {
    this.stats.bytesReceived += data.byteLength;
    this.stats.packetsReceived++;
    
    // TODO: Feed to mpegts.js player
    // This requires setting up a MediaSource manually
    // For now, we just track statistics
  }
  
  /**
   * Disconnect from stream
   */
  disconnect() {
    this.log('info', 'Disconnecting...');
    
    // Stop player
    if (this.player) {
      try {
        this.player.pause();
        this.player.unload();
        this.player.detachMediaElement();
        this.player.destroy();
        this.player = null;
      } catch (err) {
        console.error('Error destroying player:', err);
      }
    }
    
    // Close WebSocket
    if (this.connection) {
      this.connection.close();
      this.connection = null;
    }
    
    // Reset state
    this.connected = false;
    this.protocol = null;
    
    // Update UI
    this.updateStatus('disconnected', 'Disconnected');
    this.elements.connectBtn.disabled = false;
    this.elements.disconnectBtn.disabled = true;
    this.elements.currentStream.textContent = 'None';
    this.elements.currentProtocol.textContent = '-';
    this.elements.currentBitrate.textContent = '-';
    this.elements.playerOverlay.classList.remove('hidden');
    
    this.log('info', 'Disconnected');
  }
  
  /**
   * Update connection status
   */
  updateStatus(state, text) {
    this.elements.statusIndicator.className = `status-indicator ${state}`;
    this.elements.statusText.textContent = text;
  }
  
  /**
   * Update statistics
   */
  updateStats() {
    // Bytes received
    this.elements.bytesReceived.textContent = this.formatBytes(this.stats.bytesReceived);
    
    // Packets received
    this.elements.packetsReceived.textContent = this.stats.packetsReceived.toLocaleString();
    
    // Connection time
    if (this.stats.connectionStartTime) {
      const elapsed = Math.floor((Date.now() - this.stats.connectionStartTime) / 1000);
      this.elements.connectionTime.textContent = this.formatTime(elapsed);
    } else {
      this.elements.connectionTime.textContent = '0s';
    }
    
    // Buffer level
    if (this.elements.videoPlayer.buffered.length > 0) {
      const buffered = this.elements.videoPlayer.buffered.end(0) - this.elements.videoPlayer.currentTime;
      const percent = Math.min(100, Math.max(0, (buffered / 5) * 100));
      this.elements.bufferLevel.textContent = `${percent.toFixed(0)}%`;
    } else {
      this.elements.bufferLevel.textContent = '0%';
    }
  }
  
  /**
   * Log message
   */
  log(level, message) {
    const now = new Date();
    const time = now.toLocaleTimeString();
    
    const entry = document.createElement('div');
    entry.className = `log-entry ${level}`;
    entry.innerHTML = `
      <span class="log-time">[${time}]</span>
      <span class="log-level">${level.toUpperCase()}</span>
      <span class="log-message">${message}</span>
    `;
    
    this.elements.logContainer.appendChild(entry);
    
    // Auto-scroll to bottom
    this.elements.logContainer.scrollTop = this.elements.logContainer.scrollHeight;
    
    // Keep last 100 entries
    while (this.elements.logContainer.children.length > 100) {
      this.elements.logContainer.removeChild(this.elements.logContainer.firstChild);
    }
  }
  
  /**
   * Clear logs
   */
  clearLogs() {
    this.elements.logContainer.innerHTML = '';
    this.log('info', 'Logs cleared');
  }
  
  /**
   * Format bytes for display
   */
  formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
  
  /**
   * Format bitrate for display
   */
  formatBitrate(bytesPerSecond) {
    const bitsPerSecond = bytesPerSecond * 8;
    if (bitsPerSecond === 0) return '0 bps';
    const k = 1000;
    const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    const i = Math.floor(Math.log(bitsPerSecond) / Math.log(k));
    return parseFloat((bitsPerSecond / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
  
  /**
   * Format time for display
   */
  formatTime(seconds) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    
    if (h > 0) {
      return `${h}h ${m}m ${s}s`;
    } else if (m > 0) {
      return `${m}m ${s}s`;
    } else {
      return `${s}s`;
    }
  }
}

// Initialize consumer app when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    window.consumer = new StreamConsumer();
  });
} else {
  window.consumer = new StreamConsumer();
}




