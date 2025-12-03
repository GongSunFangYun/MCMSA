const express = require('express');
const crypto = require('crypto');
const querystring = require('querystring');
const axios = require('axios');
require('readline');

// Configuration
const CLIENT_ID = '4a07b708-b86d-4365-a55f-f4f23ecb85ab';
const REDIRECT_URI = 'http://localhost:3000/proxy/';
const SCOPE = 'XboxLive.signin offline_access';

// OAuth endpoints
const AUTHORIZE_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize';
const TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
const XBL_AUTH_URL = 'https://user.auth.xboxlive.com/user/authenticate';
const XSTS_AUTH_URL = 'https://xsts.auth.xboxlive.com/xsts/authorize';
const MC_LOGIN_URL = 'https://api.minecraftservices.com/authentication/login_with_xbox';
const MC_ENTITLEMENTS_URL = 'https://api.minecraftservices.com/entitlements/mcstore';
const PROFILE_URL = 'https://api.minecraftservices.com/minecraft/profile';

// PKCE
const CODE_VERIFIER = generateRandomString(32);
const CODE_CHALLENGE = generateCodeChallenge(CODE_VERIFIER);

const app = express();
const port = 3000;

// Handle OAuth callback
app.get('/proxy/', async (req, res) => {
    const authCode = req.query.code;
    if (authCode) {
        try {
            console.log('[1/6] Exchanging authorization code for Microsoft token...');
            const tokenData = await exchangeCodeForToken(authCode);
            const accessToken = tokenData.access_token;

            console.log('[2/6] Xbox Live authentication...');
            const xblData = await authenticateXboxLive(accessToken);
            const xblToken = xblData.Token;
            const userHash = xblData.DisplayClaims.xui[0].uhs;

            console.log('[3/6] XSTS authentication...');
            const xstsData = await authenticateXSTS(xblToken);
            const xstsToken = xstsData.Token;

            console.log('[4/6] Getting Minecraft access token...');
            const mcTokenData = await loginWithXbox(userHash, xstsToken);
            const mcAccessToken = mcTokenData.access_token;

            console.log('[5/6] Checking game ownership...');
            const entitlements = await checkGameOwnership(mcAccessToken);
            if (entitlements.items.length === 0) {
                throw new Error('This account does not own Minecraft');
            }

            console.log('[6/6] Getting Minecraft profile...');
            const profile = await getMinecraftProfile(mcAccessToken);

            // Build authentication result object
            const authResult = {
                timestamp: new Date().toISOString(),
                player: {
                    id: profile.id,
                    name: profile.name
                },
                tokens: {
                    microsoft: {
                        access_token: accessToken,
                        refresh_token: tokenData.refresh_token,
                        expires_in: tokenData.expires_in,
                        scope: tokenData.scope
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
                profile: profile,
                pkce: {
                    code_verifier: CODE_VERIFIER,
                    code_challenge: CODE_CHALLENGE
                }
            };

            // Output authentication results to console
            console.log('\n--- AUTHENTICATION DATA ---');
            console.log(JSON.stringify(authResult, null, 2));

            res.send('Authentication successful! Please check console for results.');

            // Setup key press exit
            processExit();

        } catch (error) {
            console.error('Authentication failed:', error.response ? JSON.stringify(error.response.data) : error.message);
            res.status(500).send(`Authentication failed: ${error.message}`);
        }
    } else {
        res.send('Authorization code not received');
    }
});

// Setup key press exit
function processExit() {
    process.exit(0);
}

// Start server
app.listen(port, () => {
    console.log('Server started on port:', port);
    console.log('Please visit the following URL for authorization:');
    console.log(generateAuthorizeUrl());
    console.log('Waiting for authorization...');
});

// Generate random string
function generateRandomString(length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex')
        .slice(0, length);
}

// Generate Code Challenge for PKCE
function generateCodeChallenge(codeVerifier) {
    const sha256 = crypto.createHash('sha256');
    const digest = sha256.update(codeVerifier).digest();
    return Buffer.from(digest).toString('base64url').replace(/=/g, '');
}

// Generate authorization URL
function generateAuthorizeUrl() {
    const params = {
        client_id: CLIENT_ID,
        response_type: 'code',
        redirect_uri: REDIRECT_URI,
        scope: SCOPE,
        code_challenge: CODE_CHALLENGE,
        code_challenge_method: 'S256',
        prompt: 'select_account',
    };

    return `${AUTHORIZE_URL}?${querystring.stringify(params)}`;
}

// Exchange authorization code for tokens
async function exchangeCodeForToken(authCode) {
    const params = {
        client_id: CLIENT_ID,
        code: authCode,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code',
        code_verifier: CODE_VERIFIER,
    };

    try {
        const response = await axios.post(TOKEN_URL, querystring.stringify(params), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });
        return response.data;
    } catch (error) {
        throw error;
    }
}

// Xbox Live authentication
async function authenticateXboxLive(accessToken) {
    const tryAuthenticate = async (rpsTicket) => {
        const data = {
            Properties: {
                AuthMethod: "RPS",
                SiteName: "user.auth.xboxlive.com",
                RpsTicket: rpsTicket
            },
            RelyingParty: "http://auth.xboxlive.com",
            TokenType: "JWT"
        };

        try {
            const response = await axios.post(XBL_AUTH_URL, data, {
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
            });
            return response.data;
        } catch (error) {
            return { error };
        }
    };

    let result = await tryAuthenticate(`d=${accessToken}`);
    if (!result.error) return result;

    result = await tryAuthenticate(accessToken);
    if (!result.error) return result;

    throw new Error(`Xbox Live authentication failed: ${JSON.stringify(result.error.response.data)}`);
}

// XSTS authentication
async function authenticateXSTS(xblToken) {
    const data = {
        Properties: {
            SandboxId: "RETAIL",
            UserTokens: [xblToken]
        },
        RelyingParty: "rp://api.minecraftservices.com/",
        TokenType: "JWT"
    };

    try {
        const response = await axios.post(XSTS_AUTH_URL, data, {
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });
        return response.data;
    } catch (error) {
        throw error;
    }
}

// Login to Minecraft with Xbox
async function loginWithXbox(userHash, xstsToken) {
    const data = {
        identityToken: `XBL3.0 x=${userHash};${xstsToken}`
    };

    try {
        const response = await axios.post(MC_LOGIN_URL, data, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        return response.data;
    } catch (error) {
        throw error;
    }
}

// Check Minecraft game ownership
async function checkGameOwnership(mcAccessToken) {
    try {
        const response = await axios.get(MC_ENTITLEMENTS_URL, {
            headers: {
                'Authorization': `Bearer ${mcAccessToken}`
            }
        });
        return response.data;
    } catch (error) {
        throw error;
    }
}

// Get Minecraft player profile
async function getMinecraftProfile(mcAccessToken) {
    try {
        const response = await axios.get(PROFILE_URL, {
            headers: {
                'Authorization': `Bearer ${mcAccessToken}`,
            },
        });
        return response.data;
    } catch (error) {
        throw error;
    }
}