/**
 * Packet Buffer for MPEG-TS Streaming
 * Receives packets from Service Worker and feeds them to video player
 */

import { sanitizeTSStream, isTSAligned } from './ts-sync.js';

export class PacketBuffer {
  constructor() {
    // PERFORMANCE: Pre-allocate ring buffer instead of growing array
    // This eliminates 7000+ array growth operations and reduces memory fragmentation
    this.maxBufferSize = 3000;
    this.buffer = new Array(this.maxBufferSize); // Pre-allocated!
    this.bufferHead = 0;  // Write index
    this.bufferTail = 0;  // Read index
    this.bufferCount = 0; // Number of packets in buffer
    
    this.mediaSource = null;
    this.sourceBuffer = null;
    this.videoElement = null;
    this.ready = false;
    this.packetsReceived = 0;
    this.packetsAppended = 0;
    this.minBufferBeforePlay = 100; // Wait for at least 100 packets before starting playback (smoother start)
    
    // TS Sync state
    this.needsInitialSync = true;  // Need to find first keyframe
    this.syncedToKeyframe = false; // Have we seen a keyframe yet?
    
    // Playback stuck detection and recovery
    this.lastPlaybackTime = 0;
    this.lastPlaybackCheck = Date.now();
    this.stuckCount = 0;
    this.STUCK_THRESHOLD = 3; // Consider stuck after 3 consecutive checks with no progress
    this.STUCK_CHECK_INTERVAL = 2000; // Check every 2 seconds
    
    // Start periodic stuck detection
    this.startStuckDetection();
  }

  /**
   * Initialize MediaSource for direct MPEG-TS playback
   */
  init(videoElement) {
    console.log('[PacketBuffer] Initializing MediaSource...');
    this.videoElement = videoElement;
    
    // Check codec support
    console.log('[PacketBuffer] Checking codec support:');
    const codecs = [
      'video/mp2t',
      'video/mp2t; codecs="avc1.42E01E"',
      'video/mp2t; codecs="avc1.42E01E,mp4a.40.2"',
      'video/mp2t; codecs="avc1.4D401E"',
      'video/mp2t; codecs="avc1.64001E"'
    ];
    
    codecs.forEach(codec => {
      console.log(`  ${codec}: ${MediaSource.isTypeSupported(codec) ? '✅ Supported' : '❌ Not supported'}`);
    });
    
    // Try simplest MIME type first (let browser detect codec)
    const mimeType = 'video/mp2t';
    if (!MediaSource.isTypeSupported(mimeType)) {
      console.error('[PacketBuffer] MPEG-TS not supported:', mimeType);
      return false;
    }
    
    console.log(`[PacketBuffer] Using MIME type: ${mimeType}`);

    this.mediaSource = new MediaSource();
    const videoUrl = URL.createObjectURL(this.mediaSource);
    this.videoElement.src = videoUrl;
    
    // Add video error handler
    this.videoElement.addEventListener('error', () => {
      if (this.videoElement.error) {
        const errorCodes = {
          1: 'MEDIA_ERR_ABORTED - Playback aborted',
          2: 'MEDIA_ERR_NETWORK - Network error',
          3: 'MEDIA_ERR_DECODE - Codec not supported or corrupt data',
          4: 'MEDIA_ERR_SRC_NOT_SUPPORTED - Media format not supported'
        };
        console.error('[Video] ERROR:', errorCodes[this.videoElement.error.code] || 'Unknown error');
        console.error('[Video] Error details:', {
          code: this.videoElement.error.code,
          message: this.videoElement.error.message
        });
      }
    });

    this.mediaSource.addEventListener('sourceopen', () => {
      console.log('[PacketBuffer] MediaSource opened');
      
      // Try codecs in order of compatibility
      const codecsToTry = [
        'video/mp2t; codecs="avc1.42E01E,mp4a.40.2"',  // H.264 Baseline + AAC
        'video/mp2t; codecs="avc1.42E01E"',            // H.264 Baseline (no audio)
        'video/mp2t; codecs="avc1.4D401E,mp4a.40.2"',  // H.264 Main + AAC
        'video/mp2t; codecs="avc1.64001E,mp4a.40.2"'   // H.264 High + AAC
      ];
      
      let sourceBufferCreated = false;
      
      for (const codec of codecsToTry) {
        try {
          console.log(`[PacketBuffer] Trying codec: ${codec}`);
          this.sourceBuffer = this.mediaSource.addSourceBuffer(codec);
          this.sourceBuffer.mode = 'sequence';
          console.log(`[PacketBuffer] ✓ Success with: ${codec}`);
          sourceBufferCreated = true;
          break;
        } catch (err) {
          console.warn(`[PacketBuffer] Failed with ${codec}:`, err.message);
        }
      }
      
      if (!sourceBufferCreated) {
        console.error('[PacketBuffer] ❌ Could not create SourceBuffer with any codec!');
        return;
      }
      
      try {
        
        this.sourceBuffer.addEventListener('updateend', () => {
          // Process more packets (don't log every time - too spammy!)
          this.processBuffer();
        });
        
        this.sourceBuffer.addEventListener('error', (e) => {
          console.error('[PacketBuffer] SourceBuffer error:', e);
        });
        
        this.ready = true;
        console.log('[PacketBuffer] ✓ Ready to receive packets');
      } catch (error) {
        console.error('[PacketBuffer] Failed to add source buffer:', error);
      }
    });

    return true;
  }

  /**
   * Add packet to buffer (called from Service Worker message handler)
   * PERFORMANCE: Uses ring buffer instead of growing array
   */
  addPacket(packetData) {
    this.packetsReceived++;
    
    if (!this.ready) {
      // Buffer packets until MediaSource is ready (use ring buffer)
      this.buffer[this.bufferHead] = packetData;
      this.bufferHead = (this.bufferHead + 1) % this.maxBufferSize;
      if (this.bufferCount < this.maxBufferSize) {
        this.bufferCount++;
      } else {
        // Overflow: move tail forward (drop oldest packet)
        this.bufferTail = (this.bufferTail + 1) % this.maxBufferSize;
      }
      return;
    }

    // Add to ring buffer
    this.buffer[this.bufferHead] = packetData;
    this.bufferHead = (this.bufferHead + 1) % this.maxBufferSize;
    if (this.bufferCount < this.maxBufferSize) {
      this.bufferCount++;
    } else {
      // Overflow: move tail forward
      this.bufferTail = (this.bufferTail + 1) % this.maxBufferSize;
    }
    
    // Debug logging every 100 packets
    if (this.packetsReceived % 100 === 0) {
      console.log(`[PacketBuffer] Received ${this.packetsReceived}, Appended ${this.packetsAppended}, Queued ${this.bufferCount}, Updating: ${this.sourceBuffer.updating}`);
    }
    
    // Start processing if source buffer is not updating
    if (!this.sourceBuffer.updating) {
      this.processBuffer();
    }
  }

  /**
   * Process buffered packets and append to SourceBuffer
   * PERFORMANCE: Direct memory copy without intermediate Uint8Array allocations
   */
  processBuffer() {
    if (!this.ready || !this.sourceBuffer || this.sourceBuffer.updating || this.bufferCount === 0) {
      return;
    }

    // Check if video element is in error state
    if (this.videoElement && this.videoElement.error) {
      console.error('[PacketBuffer] Video element has error, cannot append buffer');
      console.error('[PacketBuffer] Video error details:', {
        code: this.videoElement.error.code,
        message: this.videoElement.error.message
      });
      
      // Clear buffer and attempt recovery
      this.bufferCount = 0;
      this.bufferHead = 0;
      this.bufferTail = 0;
      this.ready = false;
      
      // Trigger MediaSource recovery
      console.log('[PacketBuffer] Attempting MediaSource recovery...');
      setTimeout(() => {
        this.reset();
      }, 1000);
      
      return;
    }

    try {
      // PERFORMANCE: Increased to 500 packets per batch for optimal throughput
      // Larger batches = fewer SourceBuffer operations = smoother playback
      // CRITICAL: Must align batches to avoid splitting MPEG-TS frames!
      const batchSize = Math.min(500, this.bufferCount);
      
      // Calculate total size AND check for proper alignment
      let totalSize = 0;
      const packets = [];
      for (let i = 0; i < batchSize; i++) {
        const idx = (this.bufferTail + i) % this.maxBufferSize;
        const packet = this.buffer[idx];
        packets.push(packet);
        totalSize += packet.byteLength;
      }
      
      // MPEG-TS FIX: Ensure total size is multiple of 188 bytes (TS packet size)
      // If not aligned, trim to last complete TS packet boundary to avoid splitting frames
      const TS_PACKET_SIZE = 188;
      if (totalSize % TS_PACKET_SIZE !== 0) {
        // Find last packet index where cumulative size is TS-aligned
        let cumulativeSize = 0;
        let alignedCount = 0;
        
        for (let i = 0; i < packets.length; i++) {
          cumulativeSize += packets[i].byteLength;
          if (cumulativeSize % TS_PACKET_SIZE === 0) {
            // This packet completes a TS boundary
            alignedCount = i + 1;
          }
        }
        
        // Trim to last aligned boundary if we found one
        if (alignedCount > 0 && alignedCount < packets.length) {
          const originalSize = totalSize;
          packets.splice(alignedCount);
          totalSize = packets.reduce((sum, p) => sum + p.byteLength, 0);
          console.log(`[PacketBuffer] TS-aligned batch: ${originalSize} → ${totalSize} bytes (${batchSize} → ${alignedCount} packets)`);
        } else if (alignedCount === 0) {
          // No aligned boundary found - this shouldn't happen but handle it
          console.warn(`[PacketBuffer] No TS-aligned boundary found in ${packets.length} packets, appending anyway`);
        }
      }
      
      // Combine into single buffer
      // PERFORMANCE FIX: Direct set() without creating intermediate Uint8Array
      const combined = new Uint8Array(totalSize);
      let offset = 0;
      for (const packet of packets) {
        // Direct memory copy - packet is already Uint8Array or ArrayBuffer
        if (packet instanceof Uint8Array) {
          combined.set(packet, offset);
        } else {
          combined.set(new Uint8Array(packet), offset);
        }
        offset += packet.byteLength;
      }
      
      // INITIAL SYNC: For first append, sanitize to start at keyframe
      let dataToAppend = combined;
      if (this.needsInitialSync) {
        console.log('[PacketBuffer] First append - checking for keyframe sync...');
        
        // Track how long we've been waiting for a keyframe
        if (!this.syncStartTime) {
          this.syncStartTime = Date.now();
        }
        
        const waitTimeMs = Date.now() - this.syncStartTime;
        const KEYFRAME_TIMEOUT_MS = 15000; // Wait 15 seconds for RAI (real keyframe)
        const allowFallback = waitTimeMs > KEYFRAME_TIMEOUT_MS;
        
        if (allowFallback && waitTimeMs <= KEYFRAME_TIMEOUT_MS + 100) {
          console.warn(`[PacketBuffer] ⚠️ No keyframe (RAI) found after ${Math.round(waitTimeMs/1000)}s, enabling fallback to PUSI/PAT...`);
          console.warn(`[PacketBuffer] ⚠️ Starting from non-keyframe may cause playback issues!`);
        }
        
        const sanitized = sanitizeTSStream(combined, allowFallback);
        
        if (sanitized && sanitized.length > 0) {
          console.log(`[PacketBuffer] ✓ Synced to keyframe, discarded ${combined.length - sanitized.length} bytes`);
          dataToAppend = sanitized;
          this.needsInitialSync = false;
          this.syncedToKeyframe = true;
          delete this.syncStartTime; // Clean up
        } else {
          console.warn('[PacketBuffer] ⚠️ No keyframe found yet, buffering...');
          // Don't append yet, wait for keyframe
          // DON'T put packets back - they're already consumed, just skip append
          // The ring buffer indices have already moved, so we just return without appending
          return; // Skip append, wait for keyframe
        }
      }
      
      // Verify alignment before appending
      if (!isTSAligned(dataToAppend)) {
        console.error('[PacketBuffer] Data not TS-aligned before append! This should not happen.');
        console.error(`  Size: ${dataToAppend.length}, First byte: 0x${dataToAppend[0].toString(16)}`);
      }
      
      // Update ring buffer indices
      this.bufferTail = (this.bufferTail + packets.length) % this.maxBufferSize;
      this.bufferCount -= packets.length;

      // Log first append for debugging
      if (!this.firstAppendDone) {
        console.log(`[PacketBuffer] First append: ${dataToAppend.length} bytes (${packets.length} packets, synced: ${this.syncedToKeyframe})`);
        this.firstAppendDone = true;
      }

      this.packetsAppended += packets.length;
      this.consecutiveErrors = 0;  // Reset error counter on successful append
      this.sourceBuffer.appendBuffer(dataToAppend.buffer);
    } catch (error) {
      console.error('[PacketBuffer] Error appending buffer:', error);
      // Clear buffer on error
      this.bufferCount = 0;
      this.bufferHead = 0;
      this.bufferTail = 0;
      
      // If error persists, attempt recovery
      if (this.consecutiveErrors === undefined) {
        this.consecutiveErrors = 0;
      }
      this.consecutiveErrors++;
      
      if (this.consecutiveErrors > 5) {
        console.error('[PacketBuffer] Too many consecutive errors, triggering recovery');
        this.ready = false;
        setTimeout(() => {
          this.reset();
        }, 1000);
      }
    }
  }

  /**
   * Trim old buffer data (only when not updating)
   */
  trimBuffer() {
    if (!this.ready || !this.sourceBuffer || this.sourceBuffer.updating) {
      return;
    }

    try {
      if (this.sourceBuffer.buffered.length > 0) {
        const bufferedEnd = this.sourceBuffer.buffered.end(this.sourceBuffer.buffered.length - 1);
        const currentTime = this.videoElement.currentTime;
        
        // Keep last 30 seconds, remove older data
        if (bufferedEnd - currentTime > 30) {
          const removeEnd = currentTime - 5; // Keep 5 seconds before current time
          if (removeEnd > 0 && this.sourceBuffer.buffered.start(0) < removeEnd) {
            this.sourceBuffer.remove(this.sourceBuffer.buffered.start(0), removeEnd);
          }
        }
      }
    } catch (error) {
      console.error('[PacketBuffer] Error trimming buffer:', error);
    }
  }

  /**
   * Get buffer statistics
   */
  getStats() {
    return {
      bufferLength: this.bufferCount,  // Use ring buffer count
      ready: this.ready,
      bufferedSeconds: this.sourceBuffer && this.sourceBuffer.buffered.length > 0
        ? this.sourceBuffer.buffered.end(this.sourceBuffer.buffered.length - 1) - this.videoElement.currentTime
        : 0
    };
  }

  /**
   * Clear all buffers
   */
  clear() {
    // Clear ring buffer
    this.bufferCount = 0;
    this.bufferHead = 0;
    this.bufferTail = 0;
    this.consecutiveErrors = 0;  // Reset error counter
    
    // Reset sync state for next stream
    this.needsInitialSync = true;
    this.syncedToKeyframe = false;
    
    if (this.sourceBuffer && !this.sourceBuffer.updating) {
      try {
        const buffered = this.sourceBuffer.buffered;
        if (buffered.length > 0) {
          this.sourceBuffer.remove(0, buffered.end(buffered.length - 1));
        }
      } catch (error) {
        console.error('[PacketBuffer] Error clearing buffer:', error);
      }
    }
  }

  /**
   * Start periodic stuck detection
   * Monitors playback progress and recovers automatically if stuck
   */
  startStuckDetection() {
    if (this.stuckDetectionInterval) {
      clearInterval(this.stuckDetectionInterval);
    }
    
    this.stuckDetectionInterval = setInterval(() => {
      if (!this.videoElement || !this.ready) return;
      
      const currentTime = this.videoElement.currentTime;
      const now = Date.now();
      const timeSinceLastCheck = now - this.lastPlaybackCheck;
      
      // Check if playback is stuck (no progress and not paused)
      if (!this.videoElement.paused && 
          currentTime === this.lastPlaybackTime && 
          currentTime > 0 &&
          timeSinceLastCheck >= this.STUCK_CHECK_INTERVAL) {
        
        this.stuckCount++;
        
        if (this.stuckCount >= this.STUCK_THRESHOLD) {
          console.warn(`[PacketBuffer] ⚠️ Playback stuck at ${currentTime.toFixed(2)}s for ${this.stuckCount * timeSinceLastCheck / 1000}s`);
          console.warn(`[PacketBuffer] Video state: readyState=${this.videoElement.readyState}, buffered=${this.getBufferedRanges()}`);
          
          // Attempt recovery
          this.recoverFromStuck();
          this.stuckCount = 0;
        } else {
          console.warn(`[PacketBuffer] ⚠️ Playback may be stuck (${this.stuckCount}/${this.STUCK_THRESHOLD})`);
        }
      } else if (currentTime !== this.lastPlaybackTime) {
        // Playback is progressing, reset stuck counter
        if (this.stuckCount > 0) {
          console.log(`[PacketBuffer] ✓ Playback resumed from ${this.lastPlaybackTime.toFixed(2)}s to ${currentTime.toFixed(2)}s`);
          this.stuckCount = 0;
        }
      }
      
      this.lastPlaybackTime = currentTime;
      this.lastPlaybackCheck = now;
    }, this.STUCK_CHECK_INTERVAL);
  }

  /**
   * Get formatted string of buffered time ranges
   */
  getBufferedRanges() {
    if (!this.videoElement) return 'N/A';
    
    const buffered = this.videoElement.buffered;
    if (!buffered || buffered.length === 0) return 'empty';
    
    const ranges = [];
    for (let i = 0; i < buffered.length; i++) {
      ranges.push(`${buffered.start(i).toFixed(2)}-${buffered.end(i).toFixed(2)}`);
    }
    return ranges.join(', ');
  }

  /**
   * Recover from stuck playback
   * Strategy: Remove problematic buffer ranges and seek slightly forward
   */
  async recoverFromStuck() {
    if (!this.videoElement || !this.sourceBuffer) return;
    
    const currentTime = this.videoElement.currentTime;
    const buffered = this.videoElement.buffered;
    
    console.log(`[PacketBuffer] 🔧 Attempting recovery from stuck at ${currentTime.toFixed(2)}s`);
    
    try {
      // Strategy 1: Remove current buffer segment (force reload)
      if (buffered.length > 0 && !this.sourceBuffer.updating) {
        // Find which buffer range contains current time
        for (let i = 0; i < buffered.length; i++) {
          const start = buffered.start(i);
          const end = buffered.end(i);
          
          if (currentTime >= start && currentTime < end) {
            // Remove a small chunk around current time to force decoder refresh
            const removeStart = Math.max(start, currentTime - 2);
            const removeEnd = Math.min(end, currentTime + 5);
            
            console.log(`[PacketBuffer] 🔧 Removing buffer range ${removeStart.toFixed(2)}-${removeEnd.toFixed(2)}s`);
            
            // Wait for any ongoing updates
            await new Promise(resolve => {
              if (!this.sourceBuffer.updating) {
                resolve();
              } else {
                this.sourceBuffer.addEventListener('updateend', resolve, { once: true });
              }
            });
            
            this.sourceBuffer.remove(removeStart, removeEnd);
            
            // Wait for removal to complete
            await new Promise(resolve => {
              this.sourceBuffer.addEventListener('updateend', resolve, { once: true });
            });
            
            console.log(`[PacketBuffer] 🔧 Buffer removed, seeking to ${(currentTime + 0.1).toFixed(2)}s`);
            
            // Strategy 2: Seek slightly forward to skip problem area
            this.videoElement.currentTime = currentTime + 0.1;
            
            // Strategy 3: Force play
            setTimeout(() => {
              if (this.videoElement.paused) {
                console.log(`[PacketBuffer] 🔧 Forcing play...`);
                this.videoElement.play().catch(err => {
                  console.error('[PacketBuffer] Play failed:', err);
                });
              }
            }, 100);
            
            break;
          }
        }
      }
    } catch (error) {
      console.error('[PacketBuffer] Recovery failed:', error);
      
      // Last resort: Full reset (only if really stuck for a long time)
      if (this.stuckCount > this.STUCK_THRESHOLD * 2) {
        console.error('[PacketBuffer] 🔧 Recovery failed multiple times, performing full reset...');
        this.reset();
      }
    }
  }

  /**
   * Reset MediaSource and reinitialize
   * Used for recovery from fatal errors
   */
  reset() {
    console.log('[PacketBuffer] Resetting MediaSource...');
    
    // Stop stuck detection during reset
    if (this.stuckDetectionInterval) {
      clearInterval(this.stuckDetectionInterval);
    }
    
    // Destroy current MediaSource
    this.destroy();
    
    // Wait a bit then reinitialize
    setTimeout(() => {
      if (this.videoElement) {
        console.log('[PacketBuffer] Reinitializing MediaSource...');
        this.init(this.videoElement);
        this.startStuckDetection();
      }
    }, 500);
  }

  /**
   * Cleanup
   */
  destroy() {
    if (this.stuckDetectionInterval) {
      clearInterval(this.stuckDetectionInterval);
      this.stuckDetectionInterval = null;
    }
    
    this.clear();
    if (this.mediaSource && this.mediaSource.readyState === 'open') {
      try {
        this.mediaSource.endOfStream();
      } catch (error) {
        // Ignore errors during cleanup
      }
    }
    this.ready = false;
    this.sourceBuffer = null;
    this.mediaSource = null;
  }
}

