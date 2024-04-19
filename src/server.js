// Import necessary modules
const WebSocket = require('ws');
const jose = require('node-jose');
const { Logging } = require('@google-cloud/logging');
const { WiliotPublicKeysArray } = require('./AuthenticationKeys'); // Adjust the import path as necessary

// Initialize Cloud Logging client
const logging = new Logging();
const log = logging.log('websocket-server-log');
const resource = { type: 'global' }; // You might adjust this based on your actual resource type in GCP

// Function to write an entry to Cloud Logging
function writeToLog(severity, message, data, userId) {
    const timestamp = new Date().toISOString();
    const jsonPayload = {
        message: message,
        ...data,
    };
    // Prepare the log entry metadata
    const entryMetadata = {
        resource: resource,
        timestamp: timestamp,
        severity: severity.toUpperCase(), // Ensure severity is always in uppercase as expected by GCP

    };

    // Prepare the jsonPayload for structured logging
    const payload = {
        resource: resource,
        timestamp: timestamp,
        jsonPayload: jsonPayload,
        labels: {
            userId: userId || 'unknown', // Include user ID in labels for easier filtering
        },
        message: jsonPayload.message? jsonPayload.message : 'No message',
    }
    // Create the log entry with jsonPayload
    const entry = log.entry(entryMetadata, payload);
    log.write(entry).catch(console.error);
}





// Flag to enable/disable token validation
let validateTokens = true;

// Function to validate the access token
async function validateAccessToken(token) {
    try {
        const keyStore = await jose.JWK.asKeyStore(WiliotPublicKeysArray);
        const result = await jose.JWS.createVerify(keyStore).verify(token);
        const payload = JSON.parse(result.payload.toString());
        return { isValid: true, data: payload }; // Token is valid
    } catch (error) {
        console.error('Token validation error:', error);
        writeToLog('CRITICAL', 'Token validation error', { error: error })
        return { isValid: false, data: {} }; // Token is invalid
    }
}

// WebSocket Server Setup
const wss = new WebSocket.Server({ port: 8081 });
console.log('WebSocket server started on port 8081');
writeToLog('INFO', 'WebSocket server started on port 8081');

wss.on('connection', async (ws, req) => {
    writeToLog('INFO', 'New WebSocket connection initiated');
    if (validateTokens) {
        const accessToken = new URL(req.url, `http://${req.headers.host}`).searchParams.get('token');
        if (!accessToken) {
            ws.close(1008, 'Access token is missing');
            writeToLog('ERROR', 'Access token is missing');
            return;
        }

        const validationResponse = await validateAccessToken(accessToken);
        writeToLog('INFO', `Token validation response: ${JSON.stringify(validationResponse)}`);
        if (!validationResponse.isValid) {
            ws.close(1008, 'Invalid access token');
            writeToLog('ERROR', 'Invalid access token');
            return;
        }
    }

    ws.on('message', async (message) => {
        let logMessage;
        try {
            logMessage = JSON.parse(message);
        } catch (e) {
            writeToLog('ERROR', 'Received an invalid message format');
            return;
        }

        const { type, message: logMsg, data, userId } = logMessage;
        let finalType = type.toLowerCase(); // Default to the type specified in the message

        // Check if the message content contains specific keywords
        if (logMsg && (logMsg.includes("CRITICAL") || logMsg.includes("ALERT"))) {
            finalType = logMsg.includes("CRITICAL") ? 'CRITICAL' : 'ALERT';
        }

        // Now call writeToLog with the potentially adjusted log type
        writeToLog(finalType.toUpperCase(), logMsg, data, userId);


        //Uncomment the following lines if you want to log the received messages to the console and for debugging purposes

        // console.log('Received message:', {
        //     type: type,
        //     message: logMsg,
        //     data: data,
        //     userId: userId,
        // });

        switch (type.toLowerCase()) {
            case 'reauth':
                const validationResponse = await validateAccessToken(data.token);
                if (validationResponse.isValid) {
                    writeToLog('INFO', 'Re-authentication successful');
                    ws.authToken = data.token;  // Storing the new token
                } else {
                    writeToLog('ERROR', 'Re-authentication failed: Invalid token');
                    ws.close(1008, 'Re-authentication failed: Invalid token');
                }
                break;
            case 'error':
            case 'warning':
            case 'info':
            case 'critical':
            case 'alert':
            case 'debug':
                // writeToLog(type, logMessage.message, data, userId);
                break;
            default:
                writeToLog('INFO', `Unhandled message type: ${message}`);
                break;
        }
    });

    // Confirm the connection
    ws.send('WebSocket connection established');
    writeToLog('INFO', 'WebSocket connection established');
});


// Function to toggle token validation
function toggleTokenValidation(enable) {
    writeToLog('INFO', `Token validation toggled: ${enable}`);
    validateTokens = enable;
}

toggleTokenValidation(true);  // You can set this based on your application needs

