// ============================================
// FRAUD DETECTION WEBHOOK SERVER
// npm install express ws
// npm start / node server.js
// ============================================

const express = require('express');
const http = require('http');
const WebSocket = require('ws');

const app = express();
app.use(express.json());

// Create HTTP server
const server = http.createServer(app);

// Create WebSocket server
const wss = new WebSocket.Server({ server });

// Store connected mobile apps
const connectedApps = new Set();

// ============================================
// WEBSOCKET CONNECTION (Mobile App)
// ============================================
wss.on('connection', (ws) => {
    console.log('📱 Mobile app connected');
    connectedApps.add(ws);

    ws.on('close', () => {
        connectedApps.delete(ws);
        console.log('📴 Mobile app disconnected');
    });
});

// Broadcast alerts to all connected apps
function sendAlertToApps(event) {
    connectedApps.forEach(ws => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(event));
        }
    });
}

// ============================================
// VAPI WEBHOOK ENDPOINT
// ============================================
app.post('/vapi-webhook', (req, res) => {
    const message = req.body.message;
    console.log('📥 Vapi Event:', message?.type);

    // 1️⃣ Transcript-based fraud detection
    if (message?.type === 'transcript') {
        const transcript = (message.transcript || '').toLowerCase();

        const fraudKeywords = [
            'otp', 'pin', 'cvv', 'password', 'blocked', 'suspended',
            'arrest', 'police', 'legal action', 'pay now', 'transfer',
            'kyc', 'verify', 'lottery', 'prize', 'winner',
            'anydesk', 'teamviewer',
            'गिरफ्तार', 'ब्लॉक', 'केवाईसी', 'पैसे भेजो'
        ];

        const detected = fraudKeywords.filter(keyword =>
            transcript.includes(keyword)
        );

        if (detected.length > 0) {
            console.log('🚨 FRAUD DETECTED:', detected);

            sendAlertToApps({
                type: 'FRAUD_ALERT',
                severity: detected.length >= 2 ? 'HIGH' : 'MEDIUM',
                keywords: detected,
                transcript: message.transcript,
                callId: message.call?.id,
                confidence: Math.min(95, detected.length * 30),
                timestamp: Date.now()
            });
        }
    }

    // 2️⃣ Honeypot tool-call logging
    if (message?.type === 'tool-calls') {
        const toolCall = message.toolCallList?.[0];

        if (toolCall?.function?.name === 'log_scam_data') {
            console.log('📝 SCAM DATA:', toolCall.function.arguments);

            sendAlertToApps({
                type: 'SCAM_DATA_CAPTURED',
                data: toolCall.function.arguments,
                callId: message.call?.id,
                timestamp: Date.now()
            });

            return res.json({
                results: [
                    {
                        toolCallId: toolCall.id,
                        result: 'Logged'
                    }
                ]
            });
        }
    }

    res.json({ success: true });
});

// ============================================
// TEST ALERT ENDPOINT (DEMO)
// ============================================
app.post('/test-alert', (req, res) => {
    sendAlertToApps({
        type: 'FRAUD_ALERT',
        severity: 'HIGH',
        keywords: ['otp', 'kyc'],
        transcript: 'Test: Please share your OTP for KYC',
        confidence: 90,
        timestamp: Date.now()
    });

    res.json({ sent: true });
});

// ============================================
// HEALTH CHECK (Render / Judges)
// ============================================
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        activeConnections: connectedApps.size,
        timestamp: Date.now()
    });
});

// ============================================
// START SERVER (Render-safe)
// ============================================
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`🛡️ Server running on port ${PORT}`);
    console.log(`Webhook: /vapi-webhook`);
    console.log(`WebSocket: wss://<your-render-url>`);
});
