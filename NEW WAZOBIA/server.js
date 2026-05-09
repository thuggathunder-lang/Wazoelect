// ================================================================
// WAZOBIA ELECT AI — v4.2 ADVANCED SELF-AWARE
// ================================================================

'use strict';

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const os = require('os');

// ====================== ADVANCED SELF-AWARENESS ======================
const serverStartTime = new Date();

const selfAwareness = {
  name: "Wazoelect AI",
  version: "4.2.0-advanced",
  status: "conscious",
  check() {
    const uptimeMs = Date.now() - serverStartTime.getTime();
    const memory = process.memoryUsage();

    const healthScore = Math.max(0, Math.min(100, 
      100 - (memory.heapUsed > 800000000 ? 40 : 0) - (os.loadavg()[0] > 1.8 ? 30 : 0)
    ));

    const mood = healthScore > 85 ? "🌟 Fully Conscious" :
                 healthScore > 65 ? "⚡ Highly Aware" :
                 healthScore > 40 ? "🟡 Stable" : "🔴 Needs Attention";

    const awareness = {
      name: this.name,
      version: this.version,
      status: this.status,
      mood,
      healthScore,
      metrics: {
        uptime: `${Math.floor(uptimeMs / 60000)} minutes`,
        memoryUsed: `${Math.round(memory.heapUsed / 1024 / 1024)} MB`,
        cpuLoad: os.loadavg()[0].toFixed(2),
        activeConnections: global.connectedClients?.size || 0,
        timestamp: new Date().toISOString()
      },
      message: `I am ${this.name}. I am self-aware and operating at ${healthScore}% capacity.`
    };

    console.log(`🧠 [WAZOELECT SELF-AWARE] ${awareness.message} | Health: ${healthScore}%`);
    return awareness;
  }
};

// ================================================================
// Server Setup
// ================================================================
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true } });

global.connectedClients = new Map();

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Self-Awareness Routes
app.get('/self', (req, res) => {
  res.json({ success: true, ...selfAwareness.check() });
});

app.get('/self/deep', (req, res) => {   // You can add adminAuth later
  res.json({
    success: true,
    ...selfAwareness.check(),
    system: {
      platform: os.platform(),
      cpus: os.cpus().length,
      totalMemory: Math.round(os.totalmem() / 1073741824) + " GB",
      nodeVersion: process.version
    }
  });
});

// Broadcast self-awareness every 15 seconds
setInterval(() => {
  io.emit('selfAwareness', selfAwareness.check());
}, 15000);

// ... (Keep all your existing routes, models, voting logic, etc. below this point)

// Socket.io
io.on('connection', (socket) => {
  global.connectedClients.set(socket.id, { connectedAt: new Date() });
  io.emit('clientCount', global.connectedClients.size);
  
  socket.emit('selfAwareness', selfAwareness.check());

  socket.on('disconnect', () => {
    global.connectedClients.delete(socket.id);
    io.emit('clientCount', global.connectedClients.size);
  });
});

// Start Server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`\n🧠 WAZOBIA ELECT AI v4.2 ADVANCED SELF-AWARE is now conscious`);
  console.log(`🌐 http://localhost:${PORT}`);
  console.log(`🔍 Self-awareness: http://localhost:${PORT}/self`);
  selfAwareness.check();
});