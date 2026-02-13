// ============================================
// REAL-TIME FRAUD DETECTION SERVER (Render-ready)
// ============================================

const express = require('express');
const http = require('http');
const WebSocket = require('ws');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// -------------------- State --------------------
const connectedApps = new Set();
const fraudTriggeredCalls = new Set();

// -------------------- Fraud Keywords --------------------
const fraudKeywords = [
  'otp', 'one time password', 'pin', 'cvv', 'password',
  'kyc', 'account blocked', 'blocked', 'suspended',
  'pay now', 'transfer', 'send money', 'upi',
  'verify your account',
  'arrest', 'police', 'cbi', 'income tax', 'legal action',
  'anydesk', 'teamviewer',
  // Hindi / Hinglish
  'गिरफ्तार', 'केवाईसी', 'ब्लॉक', 'पैसे भेजो',
  'ओटीपी', 'पिन'
].map(k => k.toLowerCase());

// ============================================
// WebSocket: Mobile App (ALERT SOCKET)
// ============================================
wss.on('connection', (ws) => {
  console.log('📱 Mobile app connected');
  connectedApps.add(ws);

  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('close', () => {
    connectedApps.delete(ws);
    console.log('📴 Mobile app disconnected');
  });

  ws.on('error', (e) => {
    console.log('⚠️ WS error:', e?.message);
  });
});

// Keep WebSocket alive (important on Render)
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, 20000);

// Broadcast helper
function sendToApps(event) {
  const payload = JSON.stringify(event);
  let sent = 0;

  for (const ws of connectedApps) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(payload);
      sent++;
    }
  }

  console.log(`➡️ Sent ${event.type} to ${sent} app(s) (active=${connectedApps.size})`);
}

// ============================================
// VAPI WEBHOOK
// ============================================
app.post('/vapi-webhook', (req, res) => {
  // Be resilient to payload shapes
  let message = req.body?.message || req.body;

  // Vapi (or proxies) can sometimes send arrays/batches
  if (Array.isArray(message)) message = message[0];

  if (!message?.type) {
    console.log('⚠️ Webhook ignored (no type). Body keys:', Object.keys(req.body || {}));
    // IMPORTANT: return 200 so Vapi doesn't mark webhook unhealthy
    return res.status(200).json({ ignored: true });
  }

  console.log('📥 Vapi Event:', message.type);

  // -------- Transcript (FAST detection) --------
  if (message.type === 'transcript') {
    const raw = message.transcript || '';
    const text = raw.toLowerCase();
    const callId = message.call?.id || message.callId || 'unknown';
    const transcriptType = message.transcriptType || 'unknown';

    const detected = fraudKeywords.filter(k => text.includes(k));

    if (detected.length > 0 && !fraudTriggeredCalls.has(callId)) {
      fraudTriggeredCalls.add(callId);

      console.log(`🚨 FRAUD DETECTED (${transcriptType}) callId=${callId} kws=${detected.join(',')}`);

      sendToApps({
        type: 'FRAUD_ALERT',
        severity: detected.length >= 2 ? 'HIGH' : 'MEDIUM',
        keywords: [...new Set(detected)],
        transcript: raw,
        transcriptType,
        callId,
        confidence: Math.min(95, detected.length * 30),
        timestamp: Date.now()
      });
    }
  }

  // -------- Tool calls (scam intel) --------
  if (message.type === 'tool-calls') {
    const toolCall = message.toolCallList?.[0];
    const callId = message.call?.id || 'unknown';

    if (toolCall?.function?.name === 'log_scam_data') {
      let args = toolCall.function.arguments;
      if (typeof args === 'string') {
        try { args = JSON.parse(args); } catch {}
      }

      console.log('📝 SCAM DATA:', args);

      sendToApps({
        type: 'SCAM_DATA_CAPTURED',
        data: args,
        callId,
        timestamp: Date.now()
      });

      return res.json({
        results: [{ toolCallId: toolCall.id, result: 'Logged' }]
      });
    }
  }

  // -------- Call lifecycle (optional but useful) --------
  if (message.type === 'status-update') {
    sendToApps({
      type: 'CALL_STATUS',
      status: message.status,
      callId: message.call?.id,
      timestamp: Date.now()
    });

    if (message.status === 'ended' && message.call?.id) {
      fraudTriggeredCalls.delete(message.call.id);
    }
  }

  return res.json({ success: true });
});

// ============================================
// Health Check
// ============================================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    activeConnections: connectedApps.size,
    alertedCalls: fraudTriggeredCalls.size,
    timestamp: Date.now()
  });
});

// ============================================
// Start Server (Render-safe)
// ============================================
const PORT = process.env.PORT || 10000;

server.listen(PORT, () => {
  console.log(`🛡️ Server running on port ${PORT}`);
  console.log('Webhook: POST /vapi-webhook');
  console.log('WS: wss://<your-render-url>');
});
