// tcp-server.test.js
// TEST FIRST: TCP/HTTP output server with Direct Sockets
// Write tests BEFORE implementing the TCP server

const { test, expect } = require('@playwright/test');
const { installIWA, waitForServiceWorker, cleanup } = require('./test-helpers.cjs');

test.describe('TCP/HTTP Output Server Tests', () => {
  let context;
  let page;
  let userDataDir;
  
  test.beforeEach(async () => {
    const result = await installIWA({ headless: false });
    context = result.context;
    page = result.page;
    userDataDir = result.userDataDir;
    
    await waitForServiceWorker(page);
  });
  
  test.afterEach(async () => {
    await cleanup(context, userDataDir);
  });
  
  test('TCP server starts on port 5001', async () => {
    const serverStatus = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => {
          resolve(event.data);
        };
        
        navigator.serviceWorker.controller.postMessage({
          type: 'GET_SERVER_STATUS'
        }, [channel.port2]);
        
        setTimeout(() => resolve({ error: 'Timeout' }), 5000);
      });
    });
    
    expect(serverStatus.tcp).toBeDefined();
    expect(serverStatus.tcp.enabled).toBe(true);
    expect(serverStatus.tcp.port).toBe(5001);
  });
  
  test('TCP server accepts HTTP connections', async () => {
    // Try to connect to HTTP server
    const response = await fetch('http://localhost:5001/stream').catch(err => null);
    
    expect(response).not.toBeNull();
    expect(response.status).toBe(200);
    expect(response.headers.get('Transfer-Encoding')).toBe('chunked');
    expect(response.headers.get('Content-Type')).toBe('application/octet-stream');
    expect(response.headers.get('X-AMT-Gateway')).toBe('true');
  });
  
  test('TCP server forwards packets as HTTP chunks', async () => {
    // Connect to stream
    const response = await fetch('http://localhost:5001/stream');
    const reader = response.body.getReader();
    
    // Inject test packet
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    // Read chunk
    const { value, done } = await reader.read();
    
    expect(done).toBe(false);
    expect(value).toBeDefined();
    expect(value.length).toBeGreaterThan(0);
    expect(value[0]).toBe(0x47); // MPEG-TS sync byte
    
    reader.releaseLock();
  });
  
  test('TCP server filters by path /stream/{source}/{group}/{port}', async () => {
    // Subscribe to specific stream via URL path
    const response = await fetch('http://localhost:5001/stream/*/232.1.2.3/1234');
    const reader = response.body.getReader();
    
    let receivedPackets = 0;
    
    // Start reading
    const readPromise = (async () => {
      try {
        while (receivedPackets < 2) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value[0] === 0x47) {
            receivedPackets++;
          }
        }
      } catch (err) {
        // Connection closed is ok
      }
    })();
    
    // Inject packet for matching group
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    // Inject packet for different group (should NOT be received)
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.4', // Different group
            groupPort: 5678
          }
        }, [channel.port2]);
      });
    });
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Should have received packet from matching group only
    expect(receivedPackets).toBe(1);
    
    reader.releaseLock();
  });
  
  test('TCP server handles multiple concurrent clients', async () => {
    // Create two concurrent connections
    const response1 = await fetch('http://localhost:5001/stream');
    const response2 = await fetch('http://localhost:5001/stream');
    
    const reader1 = response1.body.getReader();
    const reader2 = response2.body.getReader();
    
    const packets1 = [];
    const packets2 = [];
    
    // Start reading from both
    const read1 = (async () => {
      const { value } = await reader1.read();
      if (value && value[0] === 0x47) packets1.push(value);
    })();
    
    const read2 = (async () => {
      const { value } = await reader2.read();
      if (value && value[0] === 0x47) packets2.push(value);
    })();
    
    // Inject test packet
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    await Promise.all([read1, read2]);
    
    // Both clients should receive the packet
    expect(packets1.length).toBe(1);
    expect(packets2.length).toBe(1);
    
    reader1.releaseLock();
    reader2.releaseLock();
  });
  
  test('TCP server handles client disconnection', async () => {
    const response = await fetch('http://localhost:5001/stream');
    const reader = response.body.getReader();
    
    // Read one packet
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    const { value } = await reader.read();
    expect(value).toBeDefined();
    
    // Close connection
    reader.releaseLock();
    
    // Get server status - should have 0 clients now
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const serverStatus = await page.evaluate(async () => {
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => {
          resolve(event.data);
        };
        
        navigator.serviceWorker.controller.postMessage({
          type: 'GET_SERVER_STATUS'
        }, [channel.port2]);
      });
    });
    
    // Client should be cleaned up
    expect(serverStatus.tcp.clients).toBe(0);
  });
  
  test('TCP server supports query parameter filtering', async () => {
    // Subscribe via query parameters
    const response = await fetch('http://localhost:5001/stream?source=*&group=232.1.2.3&port=1234');
    const reader = response.body.getReader();
    
    // Inject matching packet
    await page.evaluate(async () => {
      const testPacket = [0x47, 0x40, 0x11, 0x10];
      return new Promise((resolve) => {
        const channel = new MessageChannel();
        channel.port1.onmessage = (event) => resolve(event.data);
        
        navigator.serviceWorker.controller.postMessage({
          type: 'INJECT_TEST_PACKET',
          data: {
            payload: testPacket,
            sourceIP: '83.97.94.146',
            groupIP: '232.1.2.3',
            groupPort: 1234
          }
        }, [channel.port2]);
      });
    });
    
    const { value, done } = await reader.read();
    
    expect(done).toBe(false);
    expect(value).toBeDefined();
    expect(value[0]).toBe(0x47);
    
    reader.releaseLock();
  });
});

