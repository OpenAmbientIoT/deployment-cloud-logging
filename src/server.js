// Import necessary modules
const WebSocket = require('ws');
const jose = require('node-jose');
const { Logging } = require('@google-cloud/logging');
const { WiliotPublicKeysArray } = require('./AuthenticationKeys'); // Adjust the import path as necessary

// Initialize Cloud Logging client
const logging = new Logging();
const log = logging.log('websocket-server-log');

const metadata = {
    resource: {type: 'global'}, // see the documentation for other resource types
};

// Function to write an entry to Cloud Logging
function writeToLog(severity, message) {
    const entry = log.entry(metadata, {
        severity: severity,
        message: message,
    });
    log.write(entry).catch(console.error);
}


// Flag to enable/disable token validation
let validateTokens = true;

// Function to validate the access token
async function validateAccessToken(token) {
    try {
        console.log('Token:', token);
        const keyStore = await jose.JWK.asKeyStore(WiliotPublicKeysArray);
        console.log('Key store:', keyStore);
        const result = await jose.JWS.createVerify(keyStore).verify(token);
        console.log('Token verification result:', result);
        const payload = JSON.parse(result.payload.toString());
        console.log('Token payload:', payload);

        return { isValid: true, data: payload }; // Token is valid
    } catch (error) {
        console.error('Token validation error:', error);
        return { isValid: false, data: {} }; // Token is invalid
    }
}

// WebSocket Server Setup
const wss = new WebSocket.Server({ port: 8081 });
console.log('WebSocket server started on port 8081');

wss.on('connection', async (ws, req) => {
    if (validateTokens) {
        // Extract token from URL query parameter
        const accessToken = new URL(req.url, `http://${req.headers.host}`).searchParams.get('token');

        if (!accessToken) {
            ws.close(1008, 'Access token is missing');
            writeToLog('ERROR', 'Access token is missing');
            return;
        }

        const validationResponse = await validateAccessToken(accessToken);
        writeToLog('INFO', `Token validation response: ${JSON.stringify(validationResponse)}`);
        console.log('Token validation response:', validationResponse);

        if (!validationResponse.isValid) {
            ws.close(1008, 'Invalid access token');
            writeToLog('ERROR', 'Invalid access token');
            return;
        }

        // Further validation can be added here (e.g., checking token expiration)
    }

    // Event listener for messages from the client
    ws.on('message', (message) => {
        // Assume the message type is included in the message, e.g., { type: 'error', data: 'Error details' }
        let logMessage;
        try {
            logMessage = JSON.parse(message);
        } catch (e) {
            writeToLog('ERROR', 'Received an invalid message format');
            return;
        }

        switch (logMessage.type) {
            case 'error':
                // Log as an error
                writeToLog('ERROR', `Error reported by client: ${logMessage.data}`);
                break;
            case 'warning':
                // Log as a warning
                writeToLog('WARNING', `Warning reported by client: ${logMessage.data}`);
                break;
            case 'info':
                // Log as an info
                writeToLog('INFO', `Info message from client: ${logMessage.data}`);
                break;

            case 'critical':
                // Log as a critical error
                writeToLog('CRITICAL', `Critical error reported by client: ${logMessage.data}`);
                break;

            case 'alert':
                // Log as an alert
                writeToLog('ALERT', `Alert from client: ${logMessage.data}`);
                break;

            case 'debug':
                // Log as a debug message
                writeToLog('DEBUG', `Debug message from client: ${logMessage.data}`);
                break;
            // Add more cases as needed
            default:
                // Log as a default info or debug message
                writeToLog('DEFAULT', `Received message: ${message}`);
                break;
        }
    });

    // Send a confirmation message to the client
    ws.send('WebSocket connection established');
    writeToLog('INFO', 'WebSocket connection established');
});

// Function to toggle token validation
function toggleTokenValidation(enable) {
    writeToLog('INFO', `Token validation toggled: ${enable}`);
    validateTokens = enable;
}

// Toggle token validation based on your needs
toggleTokenValidation(true); // Enable or disable as needed
