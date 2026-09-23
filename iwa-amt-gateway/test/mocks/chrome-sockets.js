/**
 * Mock implementation of chrome.sockets API for unit testing
 * 
 * This allows us to test UDP/TCP server logic without requiring
 * a browser environment or the actual Direct Sockets API.
 */

class MockUDPSocket {
  constructor(socketId) {
    this.socketId = socketId;
    this.bindInfo = null;
    this.receiveCallback = null;
    this.receiveErrorCallback = null;
    this.isClosed = false;
  }

  bind(address, port) {
    this.bindInfo = { address, port };
  }

  send(socketId, buffer, address, port, callback) {
    if (this.isClosed) {
      callback({ resultCode: -1 });
      return;
    }
    // Simulate successful send
    setTimeout(() => callback({ resultCode: 0, bytesSent: buffer.byteLength }), 0);
  }

  close() {
    this.isClosed = true;
    this.receiveCallback = null;
    this.receiveErrorCallback = null;
  }

  getInfo() {
    return {
      socketId: this.socketId,
      localAddress: this.bindInfo?.address || '0.0.0.0',
      localPort: this.bindInfo?.port || 0,
      ...this.bindInfo
    };
  }

  // Simulate receiving data
  simulateReceive(data, remoteAddress, remotePort) {
    if (this.receiveCallback && !this.isClosed) {
      this.receiveCallback({
        socketId: this.socketId,
        data: data.buffer,
        remoteAddress,
        remotePort
      });
    }
  }

  simulateError(error) {
    if (this.receiveErrorCallback && !this.isClosed) {
      this.receiveErrorCallback({ socketId: this.socketId, resultCode: -1 });
    }
  }
}

class MockTCPSocket {
  constructor(socketId) {
    this.socketId = socketId;
    this.bindInfo = null;
    this.listening = false;
    this.acceptCallback = null;
    this.receiveCallback = null;
    this.receiveErrorCallback = null;
    this.isClosed = false;
    this.connected = false;
    this.paused = false;
  }

  bind(address, port) {
    this.bindInfo = { address, port };
  }

  listen(backlog) {
    this.listening = true;
  }

  send(socketId, buffer, callback) {
    if (this.isClosed || !this.connected) {
      callback({ resultCode: -1 });
      return;
    }
    // Simulate successful send
    setTimeout(() => callback({ resultCode: 0, bytesSent: buffer.byteLength }), 0);
  }

  close() {
    this.isClosed = true;
    this.connected = false;
    this.listening = false;
    this.acceptCallback = null;
    this.receiveCallback = null;
    this.receiveErrorCallback = null;
  }

  disconnect() {
    this.connected = false;
  }

  setPaused(paused) {
    this.paused = paused;
  }

  getInfo() {
    return {
      socketId: this.socketId,
      localAddress: this.bindInfo?.address || '0.0.0.0',
      localPort: this.bindInfo?.port || 0,
      connected: this.connected,
      paused: this.paused,
      ...this.bindInfo
    };
  }

  // Simulate accepting a connection
  simulateAccept(clientSocketId) {
    if (this.acceptCallback && this.listening && !this.isClosed) {
      this.acceptCallback({
        socketId: this.socketId,
        clientSocketId
      });
    }
  }

  // Simulate receiving data
  simulateReceive(data) {
    if (this.receiveCallback && !this.isClosed && this.connected && !this.paused) {
      this.receiveCallback({
        socketId: this.socketId,
        data: data.buffer
      });
    }
  }

  simulateError(error) {
    if (this.receiveErrorCallback && !this.isClosed) {
      this.receiveErrorCallback({ socketId: this.socketId, resultCode: -1 });
    }
  }
}

class MockChromeSocketsUDP {
  constructor() {
    this.sockets = new Map();
    this.nextSocketId = 1;
    this.onReceiveCallbacks = [];
    this.onReceiveErrorCallbacks = [];
  }

  create(properties, callback) {
    const socketId = this.nextSocketId++;
    const socket = new MockUDPSocket(socketId);
    this.sockets.set(socketId, socket);
    setTimeout(() => callback({ socketId }), 0);
  }

  bind(socketId, address, port, callback) {
    const socket = this.sockets.get(socketId);
    if (!socket) {
      setTimeout(() => callback(-1), 0);
      return;
    }
    socket.bind(address, port);
    setTimeout(() => callback(0), 0);
  }

  send(socketId, buffer, address, port, callback) {
    const socket = this.sockets.get(socketId);
    if (!socket) {
      setTimeout(() => callback({ resultCode: -1 }), 0);
      return;
    }
    socket.send(socketId, buffer, address, port, callback);
  }

  close(socketId, callback) {
    const socket = this.sockets.get(socketId);
    if (socket) {
      socket.close();
      this.sockets.delete(socketId);
    }
    if (callback) setTimeout(() => callback(), 0);
  }

  getInfo(socketId, callback) {
    const socket = this.sockets.get(socketId);
    if (!socket) {
      setTimeout(() => callback(null), 0);
      return;
    }
    setTimeout(() => callback(socket.getInfo()), 0);
  }

  getSockets(callback) {
    const socketInfos = Array.from(this.sockets.values()).map(s => s.getInfo());
    setTimeout(() => callback(socketInfos), 0);
  }

  // Event listeners
  get onReceive() {
    return {
      addListener: (callback) => {
        this.onReceiveCallbacks.push(callback);
        // Setup callback on all existing sockets
        this.sockets.forEach(socket => {
          socket.receiveCallback = callback;
        });
      }
    };
  }

  get onReceiveError() {
    return {
      addListener: (callback) => {
        this.onReceiveErrorCallbacks.push(callback);
        // Setup callback on all existing sockets
        this.sockets.forEach(socket => {
          socket.receiveErrorCallback = callback;
        });
      }
    };
  }

  // Test helpers
  getSocket(socketId) {
    return this.sockets.get(socketId);
  }

  simulateReceive(socketId, data, remoteAddress, remotePort) {
    const socket = this.sockets.get(socketId);
    if (socket) {
      socket.simulateReceive(data, remoteAddress, remotePort);
    }
  }
}

class MockChromeSocketsTCP {
  constructor() {
    this.sockets = new Map();
    this.nextSocketId = 1;
    this.onAcceptCallbacks = [];
    this.onReceiveCallbacks = [];
    this.onReceiveErrorCallbacks = [];
  }

  create(properties, callback) {
    const socketId = this.nextSocketId++;
    const socket = new MockTCPSocket(socketId);
    this.sockets.set(socketId, socket);
    setTimeout(() => callback({ socketId }), 0);
  }

  bind(socketId, address, port, callback) {
    const socket = this.sockets.get(socketId);
    if (!socket) {
      setTimeout(() => callback(-1), 0);
      return;
    }
    socket.bind(address, port);
    setTimeout(() => callback(0), 0);
  }

  listen(socketId, address, port, backlog, callback) {
    const socket = this.sockets.get(socketId);
    if (!socket) {
      setTimeout(() => callback(-1), 0);
      return;
    }
    socket.listen(backlog);
    setTimeout(() => callback(0), 0);
  }

  connect(socketId, address, port, callback) {
    const socket = this.sockets.get(socketId);
    if (!socket) {
      setTimeout(() => callback(-1), 0);
      return;
    }
    socket.connected = true;
    setTimeout(() => callback(0), 0);
  }

  send(socketId, buffer, callback) {
    const socket = this.sockets.get(socketId);
    if (!socket) {
      setTimeout(() => callback({ resultCode: -1 }), 0);
      return;
    }
    socket.send(socketId, buffer, callback);
  }

  close(socketId, callback) {
    const socket = this.sockets.get(socketId);
    if (socket) {
      socket.close();
      this.sockets.delete(socketId);
    }
    if (callback) setTimeout(() => callback(), 0);
  }

  disconnect(socketId, callback) {
    const socket = this.sockets.get(socketId);
    if (socket) {
      socket.disconnect();
    }
    if (callback) setTimeout(() => callback(), 0);
  }

  setPaused(socketId, paused, callback) {
    const socket = this.sockets.get(socketId);
    if (socket) {
      socket.setPaused(paused);
    }
    if (callback) setTimeout(() => callback(), 0);
  }

  getInfo(socketId, callback) {
    const socket = this.sockets.get(socketId);
    if (!socket) {
      setTimeout(() => callback(null), 0);
      return;
    }
    setTimeout(() => callback(socket.getInfo()), 0);
  }

  getSockets(callback) {
    const socketInfos = Array.from(this.sockets.values()).map(s => s.getInfo());
    setTimeout(() => callback(socketInfos), 0);
  }

  // Event listeners
  get onAccept() {
    return {
      addListener: (callback) => {
        this.onAcceptCallbacks.push(callback);
        this.sockets.forEach(socket => {
          socket.acceptCallback = callback;
        });
      }
    };
  }

  get onReceive() {
    return {
      addListener: (callback) => {
        this.onReceiveCallbacks.push(callback);
        this.sockets.forEach(socket => {
          socket.receiveCallback = callback;
        });
      }
    };
  }

  get onReceiveError() {
    return {
      addListener: (callback) => {
        this.onReceiveErrorCallbacks.push(callback);
        this.sockets.forEach(socket => {
          socket.receiveErrorCallback = callback;
        });
      }
    };
  }

  // Test helpers
  getSocket(socketId) {
    return this.sockets.get(socketId);
  }

  simulateAccept(serverSocketId, clientSocketId) {
    const socket = this.sockets.get(serverSocketId);
    if (socket) {
      // Create client socket
      const clientSocket = new MockTCPSocket(clientSocketId);
      clientSocket.connected = true;
      this.sockets.set(clientSocketId, clientSocket);
      
      // Trigger accept callback
      socket.simulateAccept(clientSocketId);
    }
  }

  simulateReceive(socketId, data) {
    const socket = this.sockets.get(socketId);
    if (socket) {
      socket.simulateReceive(data);
    }
  }
}

// Create global mock chrome object
function setupChromeMocks() {
  global.chrome = {
    sockets: {
      udp: new MockChromeSocketsUDP(),
      tcp: new MockChromeSocketsTCP()
    }
  };
  return global.chrome;
}

function resetChromeMocks() {
  if (global.chrome) {
    global.chrome.sockets.udp = new MockChromeSocketsUDP();
    global.chrome.sockets.tcp = new MockChromeSocketsTCP();
  }
}

module.exports = {
  MockUDPSocket,
  MockTCPSocket,
  MockChromeSocketsUDP,
  MockChromeSocketsTCP,
  setupChromeMocks,
  resetChromeMocks
};




