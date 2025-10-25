/**
 * OPTIMIZED Packet Buffer with Zero-Copy Ring Buffer
 * Eliminates excessive memory allocations and copies
 */

export class PacketBufferOptimized {
  constructor() {
    // Pre-allocated ring buffer (4MB continuous memory)
    this.ringBufferSize = 4 * 1024 * 1024; // 4MB
    this.ringBuffer = new ArrayBuffer(this.ringBufferSize);
    this.ringBufferView = new Uint8Array(this.ringBuffer);
    
    // Write/read pointers
    this.writePos = 0;
    this.readPos = 0;
    this.bufferedBytes = 0;
    
    // MediaSource
    this.mediaSource = null;
    this.sourceBuffer = null;
    this.videoElement = null;
    this.ready = false;
    
    // Stats
    this.packetsReceived = 0;
    this.packetsAppended = 0;
    this.bytesAppended = 0;
    
    // Append control
    this.isAppending = false;
    this.minBytesForAppend = 64 * 1024; // 64KB minimum batch (much larger!)
    this.maxBytesForAppend = 512 * 1024; // 512KB maximum batch
    
    // Performance monitoring
    this.lastAppendTime = 0;
    this.appendCount = 0;
  }

  /**
   * Initialize MediaSource for direct MPEG-TS playback
   */
  init(videoElement) {
    console.log('[PacketBuffer] Initializing OPTIMIZED MediaSource with zero-copy ring buffer...');
    this.videoElement = videoElement;
    
    // Check codec support
    const mimeType = 'video/mp2t';
    if (!MediaSource.isTypeSupported(mimeType)) {
      console.error('[PacketBuffer] MPEG-TS not supported');
      return false;
    }

    this.mediaSource = new MediaSource();
    const videoUrl = URL.createObjectURL(this.mediaSource);
    this.videoElement.src = videoUrl;
    
    this.videoElement.addEventListener('error', () => {
      if (this.videoElement.error) {
        console.error('[PacketBuffer] Video error:', this.videoElement.error.code);
      }
    });

    this.mediaSource.addEventListener('sourceopen', () => {
      console.log('[PacketBuffer] MediaSource opened');
      
      const codecsToTry = [
        'video/mp2t; codecs="avc1.42E01E,mp4a.40.2"',
        'video/mp2t; codecs="avc1.42E01E"',
        'video/mp2t; codecs="avc1.4D401E,mp4a.40.2"'
      ];
      
      for (const codec of codecsToTry) {
        try {
          this.sourceBuffer = this.mediaSource.addSourceBuffer(codec);
          this.sourceBuffer.mode = 'sequence';
          console.log(`[PacketBuffer] ✓ Using codec: ${codec}`);
          break;
        } catch (err) {
          console.warn(`[PacketBuffer] Failed codec ${codec}`);
        }
      }
      
      if (!this.sourceBuffer) {
        console.error('[PacketBuffer] No codec worked!');
        return;
      }
      
      this.sourceBuffer.addEventListener('updateend', () => {
        this.isAppending = false;
        this.processBuffer();
      });
      
      this.sourceBuffer.addEventListener('error', (e) => {
        console.error('[PacketBuffer] SourceBuffer error:', e);
        this.isAppending = false;
      });
      
      this.ready = true;
      console.log('[PacketBuffer] ✓ Ready (ring buffer mode)');
      console.log(`[PacketBuffer] Ring buffer: ${(this.ringBufferSize / 1024 / 1024).toFixed(1)}MB`);
    });

    return true;
  }

  /**
   * Add packet to ring buffer - ZERO COPY!
   * Just write directly to pre-allocated buffer
   */
  addPacket(packetData) {
    this.packetsReceived++;
    
    if (!this.ready) {
      return; // Drop packets until ready
    }

    const packetSize = packetData.byteLength;
    
    // Check if we have space (with wraparound)
    const availableSpace = this.ringBufferSize - this.bufferedBytes;
    if (packetSize > availableSpace) {
      console.warn('[PacketBuffer] Ring buffer full! Dropping packet');
      return;
    }
    
    // Write packet to ring buffer (handles wraparound)
    const packetView = new Uint8Array(packetData);
    
    if (this.writePos + packetSize <= this.ringBufferSize) {
      // Simple case: no wraparound
      this.ringBufferView.set(packetView, this.writePos);
      this.writePos += packetSize;
    } else {
      // Wraparound case
      const firstPart = this.ringBufferSize - this.writePos;
      this.ringBufferView.set(packetView.subarray(0, firstPart), this.writePos);
      this.ringBufferView.set(packetView.subarray(firstPart), 0);
      this.writePos = packetSize - firstPart;
    }
    
    // Handle writePos wraparound
    if (this.writePos >= this.ringBufferSize) {
      this.writePos = 0;
    }
    
    this.bufferedBytes += packetSize;
    
    // Debug logging
    if (this.packetsReceived % 500 === 0) {
      const bufferUsage = ((this.bufferedBytes / this.ringBufferSize) * 100).toFixed(1);
      console.log(`[PacketBuffer] Rx:${this.packetsReceived}, Buffered:${(this.bufferedBytes/1024).toFixed(1)}KB (${bufferUsage}%), Appending:${this.isAppending}`);
    }
    
    // Try to append if not already appending
    if (!this.isAppending && this.bufferedBytes >= this.minBytesForAppend) {
      this.processBuffer();
    }
  }

  /**
   * Process ring buffer and append to SourceBuffer - OPTIMIZED!
   * Uses subarray (zero-copy view) instead of copying data
   */
  processBuffer() {
    if (!this.ready || !this.sourceBuffer || this.isAppending || this.bufferedBytes === 0) {
      return;
    }

    // Determine batch size (bytes to append)
    const batchSize = Math.min(this.maxBytesForAppend, this.bufferedBytes);
    
    if (batchSize < this.minBytesForAppend && this.packetsReceived < 100) {
      // Wait for more data (unless we're just starting)
      return;
    }

    try {
      this.isAppending = true;
      
      // Create view into ring buffer (ZERO COPY!)
      let dataToAppend;
      
      if (this.readPos + batchSize <= this.ringBufferSize) {
        // Simple case: no wraparound - use subarray (zero-copy view!)
        dataToAppend = this.ringBufferView.subarray(this.readPos, this.readPos + batchSize);
        this.readPos += batchSize;
      } else {
        // Wraparound case: need to copy (unavoidable)
        const firstPart = this.ringBufferSize - this.readPos;
        const secondPart = batchSize - firstPart;
        dataToAppend = new Uint8Array(batchSize);
        dataToAppend.set(this.ringBufferView.subarray(this.readPos, this.ringBufferSize), 0);
        dataToAppend.set(this.ringBufferView.subarray(0, secondPart), firstPart);
        this.readPos = secondPart;
      }
      
      // Handle readPos wraparound
      if (this.readPos >= this.ringBufferSize) {
        this.readPos = 0;
      }
      
      this.bufferedBytes -= batchSize;
      
      // Append to MediaSource
      this.sourceBuffer.appendBuffer(dataToAppend);
      this.packetsAppended++;
      this.bytesAppended += batchSize;
      this.appendCount++;
      
      // Performance stats
      const now = performance.now();
      if (this.appendCount % 10 === 0) {
        const timeSinceLastLog = now - this.lastAppendTime;
        const appendRate = timeSinceLastLog > 0 ? (10000 / timeSinceLastLog).toFixed(1) : 0;
        console.log(`[PacketBuffer] Append #${this.appendCount}: ${(batchSize/1024).toFixed(1)}KB, Rate: ${appendRate}/sec, Total: ${(this.bytesAppended/1024/1024).toFixed(1)}MB`);
        this.lastAppendTime = now;
      }
      
    } catch (error) {
      console.error('[PacketBuffer] Append error:', error);
      this.isAppending = false;
      
      // Reset on error
      if (error.name === 'QuotaExceededError') {
        console.log('[PacketBuffer] Quota exceeded, trimming buffer...');
        this.trimBuffer();
      }
    }
  }

  /**
   * Trim old buffered data from MediaSource
   */
  trimBuffer() {
    if (!this.videoElement || !this.sourceBuffer) return;
    
    try {
      const currentTime = this.videoElement.currentTime;
      const buffered = this.sourceBuffer.buffered;
      
      if (buffered.length > 0) {
        const start = buffered.start(0);
        const end = buffered.end(buffered.length - 1);
        
        // Keep last 30 seconds
        const removeEnd = Math.max(0, currentTime - 30);
        
        if (removeEnd > start && !this.sourceBuffer.updating) {
          console.log(`[PacketBuffer] Trimming: ${start.toFixed(1)}s to ${removeEnd.toFixed(1)}s (keeping ${(end - removeEnd).toFixed(1)}s)`);
          this.sourceBuffer.remove(start, removeEnd);
        }
      }
    } catch (error) {
      console.error('[PacketBuffer] Trim error:', error);
    }
  }

  /**
   * Clear ring buffer
   */
  clear() {
    console.log('[PacketBuffer] Clearing ring buffer...');
    this.writePos = 0;
    this.readPos = 0;
    this.bufferedBytes = 0;
    this.isAppending = false;
    this.packetsReceived = 0;
    this.packetsAppended = 0;
    this.bytesAppended = 0;
  }

  /**
   * Reset and reinitialize
   */
  reset() {
    console.log('[PacketBuffer] Resetting...');
    this.clear();
    if (this.sourceBuffer && !this.sourceBuffer.updating) {
      try {
        this.sourceBuffer.abort();
      } catch (e) {
        console.warn('[PacketBuffer] Abort error:', e);
      }
    }
  }

  /**
   * Get buffer statistics
   */
  getStats() {
    return {
      packetsReceived: this.packetsReceived,
      packetsAppended: this.packetsAppended,
      bytesAppended: this.bytesAppended,
      bufferedBytes: this.bufferedBytes,
      bufferUsage: (this.bufferedBytes / this.ringBufferSize * 100).toFixed(1) + '%',
      isAppending: this.isAppending
    };
  }
}


