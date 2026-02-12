// ============================================
// FRAUD DETECTION WEBHOOK SERVER
// npm install express ws
// node server.js
// ============================================

const express = require('express');
const http = require('http');
const WebSocket = require('ws');

const app = express();
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const connectedApps = new Set();

// Mobile app connects via WebSocket
wss.on('connection', (ws) => {
    console.log('📱 Mobile app connected');
    connectedApps.add(ws);

    ws.on('close', () => {
        connectedApps.delete(ws);
        console.log('📴 Mobile app disconnected');
    });
});

// Broadcast alerts
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

    // 1️⃣ Transcript fraud detection
    if (message?.type === 'transcript') {
        const transcript = (message.transcript || '').toLowerCase();

        const fraudKeywords = [
            'otp', 'pin', 'cvv', 'password', 'blocked', 'suspended',
            'arrest', 'police', 'legal action', 'pay now', 'transfer',
            'kyc', 'verify', 'lottery', 'prize', 'winner',
            'anydesk', 'teamviewer',
            'गिरफ्तार', 'ब्लॉक', 'केवाईसी', 'पैसे भेजो'
        ];

        const detected = fraudKeywords.filter(k => transcript.includes(k));

        if (detected.length > 0) {
            console.log('🚨 FRAUD DETECTED:', detected);

            sendAlertToApps({
                type: 'FRAUD_ALERT',
                severity: detected.length >= 2 ? 'HIGH' : 'MEDIUM',
                keywords: detected,
                transcript: message.transcript,
                callId: message.call?.id,
                timestamp: Date.now()
            });
        }
    }

    // 2️⃣ Tool call logging (honeypot intelligence)
    if (message?.type === 'tool-calls') {
        const toolCall = message.toolCallList?.[0];

        if (toolCall?.function?.name === 'log_scam_data') {
            console.log('📝 SCAM DATA:', toolCall.function.arguments);

            sendAlertToApps({
                type: 'SCAM_DATA_CAPTURED',
                data: toolCall.function.arguments,
                callId: message.call?.id
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
// TEST ALERT (for demo)
// ============================================
app.post('/test-alert', (req, res) => {
    sendAlertToApps({
        type: 'FRAUD_ALERT',
        severity: 'HIGH',
        keywords: ['otp', 'kyc'],
        transcript: 'Test: Please share your OTP for KYC',
        timestamp: Date.now()
    });

    res.json({ sent: true });
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`🛡️ Server running on port ${PORT}`);
    console.log(`Webhook: http://localhost:${PORT}/vapi-webhook`);
    console.log(`WebSocket: ws://localhost:${PORT}`);
});
