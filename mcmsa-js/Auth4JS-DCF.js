const axios = require('axios');

// Configuration
const CLIENT_ID = '4a07b708-b86d-4365-a55f-f4f23ecb85ab';
const SCOPE = 'XboxLive.signin offline_access openid profile email';

// OAuth endpoints
const DEVICE_CODE_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode';
const TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
const XBL_AUTH_URL = 'https://user.auth.xboxlive.com/user/authenticate';
const XSTS_AUTH_URL = 'https://xsts.auth.xboxlive.com/xsts/authorize';
const MC_LOGIN_URL = 'https://api.minecraftservices.com/authentication/login_with_xbox';
const PROFILE_URL = 'https://api.minecraftservices.com/minecraft/profile';

async function startDeviceAuth() {
    console.log('Minecraft Authentication - Device Code Flow\n');

    try {
        console.log('[1/7] Requesting device code...');
        const deviceCodeResponse = await requestDeviceCode();

        console.log('\nVisit this URL: ' + deviceCodeResponse.verification_uri);
        console.log('Enter this code: ' + deviceCodeResponse.user_code);
        console.log('\nWaiting for authentication...');

        console.log('[2/7] Polling for token...');
        const tokenResponse = await pollForToken(deviceCodeResponse.device_code, deviceCodeResponse.interval);

        console.log('[3/7] Microsoft token obtained');

        console.log('[4/7] Xbox Live authentication...');
        const xblData = await authenticateWithXboxLive(tokenResponse.access_token);
        const xblToken = xblData.Token;
        const userHash = xblData.DisplayClaims.xui[0].uhs;

        console.log('[5/7] XSTS authentication...');
        const xstsData = await authenticateWithXSTS(xblToken);
        const xstsToken = xstsData.Token;

        console.log('[6/7] Minecraft login...');
        const mcTokenData = await loginToMinecraft(userHash, xstsToken);
        const mcAccessToken = mcTokenData.access_token;

        console.log('[7/7] Getting profile...');
        const profile = await getMinecraftProfile(mcAccessToken);
        const playerUUID = profile.id;
        const playerName = profile.name;

        // Build authentication result object
        const authResult = {
            timestamp: new Date().toISOString(),
            player: {
                id: playerUUID,
                name: playerName
            },
            tokens: {
                microsoft: {
                    access_token: tokenResponse.access_token,
                    refresh_token: tokenResponse.refresh_token,
                    expires_in: tokenResponse.expires_in,
                    scope: tokenResponse.scope
                },
                xbox: {
                    xbl_token: xblToken,
                    xsts_token: xstsToken
                },
                minecraft: {
                    access_token: mcAccessToken,
                    expires_in: mcTokenData.expires_in
                }
            },
            profile: profile
        };

        // Output results to console
        console.log('\n--- AUTHENTICATION DATA ---');
        console.log(JSON.stringify(authResult, null, 2));

        // Return the result for further processing if needed
        return authResult;

    } catch (error) {
        console.error('Error: ' + error.message);
        process.exit(1);
    }
}

async function requestDeviceCode() {
    const params = new URLSearchParams();
    params.append('client_id', CLIENT_ID);
    params.append('scope', SCOPE);

    const response = await axios.post(DEVICE_CODE_URL, params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    return response.data;
}

async function pollForToken(deviceCode, interval) {
    const params = new URLSearchParams();
    params.append('grant_type', 'urn:ietf:params:oauth:grant-type:device_code');
    params.append('client_id', CLIENT_ID);
    params.append('device_code', deviceCode);

    const pollInterval = (interval || 5) * 1000;
    const maxAttempts = 180;

    for (let i = 0; i < maxAttempts; i++) {
        try {
            const response = await axios.post(TOKEN_URL, params.toString(), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            if (response.data.access_token) {
                return response.data;
            }
        } catch (error) {
            if (error.response?.data?.error === 'authorization_pending') {
                await new Promise(resolve => setTimeout(resolve, pollInterval));
                continue;
            }
            throw error;
        }
    }

    throw new Error('Authentication timeout - please try again');
}

async function authenticateWithXboxLive(accessToken) {
    const tryAuth = async (rpsTicket) => {
        try {
            const payload = {
                Properties: {
                    AuthMethod: "RPS",
                    SiteName: "user.auth.xboxlive.com",
                    RpsTicket: rpsTicket
                },
                RelyingParty: "http://auth.xboxlive.com",
                TokenType: "JWT"
            };

            const response = await axios.post(XBL_AUTH_URL, payload, {
                headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
            });

            return response.data;
        } catch (error) {
            return null;
        }
    };

    const result1 = await tryAuth(`d=${accessToken}`);
    if (result1) return result1;

    const result2 = await tryAuth(accessToken);
    if (result2) return result2;

    throw new Error('Xbox Live authentication failed');
}

async function authenticateWithXSTS(xblToken) {
    const payload = {
        Properties: {
            SandboxId: "RETAIL",
            UserTokens: [xblToken]
        },
        RelyingParty: "rp://api.minecraftservices.com/",
        TokenType: "JWT"
    };

    const response = await axios.post(XSTS_AUTH_URL, payload, {
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' }
    });

    return response.data;
}

async function loginToMinecraft(userHash, xstsToken) {
    const payload = {
        identityToken: `XBL3.0 x=${userHash};${xstsToken}`
    };

    const response = await axios.post(MC_LOGIN_URL, payload, {
        headers: { 'Content-Type': 'application/json' }
    });

    return response.data;
}

async function getMinecraftProfile(mcAccessToken) {
    const response = await axios.get(PROFILE_URL, {
        headers: { 'Authorization': `Bearer ${mcAccessToken}` }
    });

    return response.data;
}

// Handle exit signals
process.on('SIGINT', () => {
    process.exit(0);
});

// Start authentication process
startDeviceAuth();