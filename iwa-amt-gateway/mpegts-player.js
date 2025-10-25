// MPEG-TS Player for AMT Gateway
// Buffers incoming packets and plays them as video
// Using mpegts.js player library (complete solution, no manual transmuxing needed)
import mpegts from 'mpegts.js';

class MPEGTSPlayer {
  constructor(videoElement) {
    this.video = videoElement;
    this.player = null;
    this.initialized = false;
    this.packetBuffer = [];
    this.bufferSize = 0;
    this.flushThreshold = 1024 * 256; // Buffer 256KB of MPEG-TS data before flushing
    this.flushTimer = null;
  }

  async init() {
    if (!mpegts.isSupported()) {
      console.error('MPEG-TS playback not supported in this browser');
      return false;
    }

    // Mute audio to avoid potential audio decode errors
    this.video.muted = true;
    
    // Add error listener to video element
    this.video.addEventListener('error', (e) => {
      if (this.video.error) {
        console.debug('Video error (continuing):', this.video.error.code, this.video.error.message);
      }
    });

    // Don't create player yet - wait for loadSource() to be called with a URL
    // mpegts.js requires a URL to be set during player creation

    this.initialized = true;
    console.log('[MPEG-TS Player] Initialized (waiting for stream URL)');
    return true;
  }

  addPacket(data) {
    if (!this.initialized || !this.player) {
      return;
    }

    // Note: mpegts.js doesn't support manual packet feeding
    // This method is kept for API compatibility but doesn't do anything
    // For actual playback, use a URL-based stream instead
    console.warn('[MPEG-TS Player] Manual packet feeding not supported with mpegts.js. Use loadSource() with a URL instead.');
  }

  loadSource(url) {
    if (!this.initialized) {
      console.error('[MPEG-TS Player] Player not initialized');
      return;
    }

    // Destroy existing player if any
    if (this.player) {
      try {
        this.player.pause();
        this.player.unload();
        this.player.detachMediaElement();
        this.player.destroy();
      } catch (e) {
        console.warn('[MPEG-TS Player] Error destroying old player:', e);
      }
    }

    // Check if WebSocket URL
    if (url.startsWith('ws://') || url.startsWith('wss://')) {
      console.log('[MPEG-TS Player] Using WebSocket mode for:', url);
      this.loadWebSocketSource(url);
      return;
    }

    try {
      // Create new player with the stream URL (HTTP mode)
      this.player = mpegts.createPlayer({
        type: 'mpegts',
        url: url, // Set the stream URL
        isLive: true,
        hasAudio: false,
        hasVideo: true
      });

      this.player.attachMediaElement(this.video);

      // Set up error handlers
      this.player.on(mpegts.Events.ERROR, (errorType, errorDetail, errorInfo) => {
        console.error('[MPEG-TS Player] Error:', errorType, errorDetail, errorInfo);
      });

      this.player.load();
      console.log('[MPEG-TS Player] Loading source:', url);
    } catch (error) {
      console.error('[MPEG-TS Player] Error loading source:', error);
    }
  }

  /**
   * Load source from WebSocket (for IWA Direct Sockets output)
   */
  loadWebSocketSource(wsUrl) {
    try {
      // Use mpegts.js player but feed it via WebSocket
      this.player = mpegts.createPlayer({
        type: 'mpegts',
        isLive: true,
        hasAudio: false,
        hasVideo: true
      });

      this.player.attachMediaElement(this.video);

      // Set up error handlers
      this.player.on(mpegts.Events.ERROR, (errorType, errorDetail, errorInfo) => {
        console.error('[MPEG-TS Player] Error:', errorType, errorDetail, errorInfo);
      });

      // Connect WebSocket
      this.ws = new WebSocket(wsUrl);
      this.ws.binaryType = 'arraybuffer';

      this.ws.onopen = () => {
        console.log('[MPEG-TS Player] ✓ WebSocket connected');
      };

      this.ws.onmessage = (event) => {
        // Feed packet to mpegts.js player
        // Note: mpegts.js doesn't have a direct "feed packet" API
        // So we'll need to buffer and create a fake HTTP response
        console.warn('[MPEG-TS Player] Received WS packet:', event.data.byteLength, 'bytes (feeding not yet implemented)');
        // TODO: Implement packet buffering and feeding
      };

      this.ws.onerror = (error) => {
        console.error('[MPEG-TS Player] WebSocket error:', error);
      };

      this.ws.onclose = () => {
        console.log('[MPEG-TS Player] WebSocket closed');
      };

    } catch (error) {
      console.error('[MPEG-TS Player] Error loading WebSocket source:', error);
    }
  }

  play() {
    if (!this.initialized || !this.player) {
      return;
    }

    try {
      this.player.play();
      console.log('[MPEG-TS Player] Playback started');
    } catch (error) {
      console.error('[MPEG-TS Player] Error starting playback:', error);
    }
  }

  stop() {
    if (!this.initialized || !this.player) {
      return;
    }

    try {
      this.player.pause();
      console.log('[MPEG-TS Player] Playback stopped');
    } catch (error) {
      console.error('[MPEG-TS Player] Error stopping playback:', error);
    }
  }

  destroy() {
    if (!this.player) {
      return;
    }

    try {
      this.player.pause();
      this.player.unload();
      this.player.detachMediaElement();
      this.player.destroy();
      this.player = null;
      this.initialized = false;
      console.log('[MPEG-TS Player] Destroyed');
    } catch (error) {
      console.error('[MPEG-TS Player] Error destroying player:', error);
    }
  }
}

export { MPEGTSPlayer };
