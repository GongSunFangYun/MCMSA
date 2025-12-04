const axios = require('axios');

const CLIENT_ID = '4a07b708-b86d-4365-a55f-f4f23ecb85ab';
const SCOPE = 'XboxLive.signin offline_access openid profile email';

const DEVICE_CODE_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode';
const TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
const XBL_AUTH_URL = 'https://user.auth.xboxlive.com/user/authenticate';
const XSTS_AUTH_URL = 'https://xsts.auth.xboxlive.com/xsts/authorize';
const MC_LOGIN_URL = 'https://api.minecraftservices.com/authentication/login_with_xbox';
const PROFILE_URL = 'https://api.minecraftservices.com/minecraft/profile';

// noinspection JSUnresolvedReference
class MinecraftAuthenticator {
    constructor() {
        this.client = axios.create({
            timeout: 30000,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
        });
    }

    async authenticate() {
        console.log('Minecraft Authentication - Device Code Flow\n');

        try {
            console.log('[1/6] Requesting device code...');
            const deviceCodeResponse = await this.requestDeviceCode();

            console.log(`\nVisit this URL: ${deviceCodeResponse.verification_uri}`);
            console.log(`Enter this code: ${deviceCodeResponse.user_code}`);
            console.log('Waiting for authentication...');

            const tokenResponse = await this.pollForToken(deviceCodeResponse.device_code, deviceCodeResponse.interval);
            console.log('\n[2/6] Polling for token...');

            const xblData = await this.authenticateWithXboxLive(tokenResponse.access_token);
            const xblToken = xblData.Token;
            const userHash = xblData.DisplayClaims.xui[0].uhs;
            console.log('[3/6] Xbox Live authentication...');

            const xstsData = await this.authenticateWithXSTS(xblToken);
            const xstsToken = xstsData.Token;
            console.log('[4/6] XSTS authentication...');

            const mcTokenData = await this.loginToMinecraft(userHash, xstsToken);
            const mcAccessToken = mcTokenData.access_token;
            console.log('[5/6] Minecraft login...');

            const profile = await this.getMinecraftProfile(mcAccessToken);
            console.log('[6/6] Getting profile...');

            return {
                tokens: {
                    microsoft_access_token: tokenResponse.access_token,
                    microsoft_refresh_token: tokenResponse.refresh_token,
                    xbl_token: xblToken,
                    xsts_token: xstsToken,
                    minecraft_access_token: mcAccessToken,
                    expires_in: mcTokenData.expires_in
                },
                profile: profile
            };

        } catch (e) {
            console.log(`Authentication failed: ${e.message}`);
            throw e;
        }
    }

    async requestDeviceCode() {
        const formData = new URLSearchParams();
        formData.append('client_id', CLIENT_ID);
        formData.append('scope', SCOPE);

        const response = await this.client.post(DEVICE_CODE_URL, formData, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        return response.data;
    }

    async pollForToken(deviceCode, interval) {
        const pollInterval = Math.max(interval, 5) * 1000;
        const maxAttempts = 180;

        for (let attempt = 0; attempt < maxAttempts; attempt++) {
            try {
                const formData = new URLSearchParams();
                formData.append('grant_type', 'urn:ietf:params:oauth:grant-type:device_code');
                formData.append('client_id', CLIENT_ID);
                formData.append('device_code', deviceCode);

                const response = await this.client.post(TOKEN_URL, formData, {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                });

                return response.data;
            } catch (error) {
                if (error.response && error.response.data) {
                    const errorData = error.response.data;
                    if (errorData.error === 'authorization_pending') {
                        await this.sleep(pollInterval);
                        continue;
                    } else {
                        throw new Error(`Token polling error: ${JSON.stringify(errorData)}`);
                    }
                }

                if (attempt === maxAttempts - 1) {
                    throw new Error('Authentication timeout - please try again');
                }

                await this.sleep(pollInterval);
            }
        }

        throw new Error('Authentication timeout - please try again');
    }

    async authenticateWithXboxLive(accessToken) {
        const attempts = [`d=${accessToken}`, accessToken];

        for (const rpsTicket of attempts) {
            try {
                const requestBody = {
                    Properties: {
                        AuthMethod: 'RPS',
                        SiteName: 'user.auth.xboxlive.com',
                        RpsTicket: rpsTicket
                    },
                    RelyingParty: 'http://auth.xboxlive.com',
                    TokenType: 'JWT'
                };

                const response = await this.client.post(XBL_AUTH_URL, requestBody);
                return response.data;
            } catch (error) {
                continue;
            }
        }

        throw new Error('Xbox Live authentication failed with both RPS ticket formats');
    }

    async authenticateWithXSTS(xblToken) {
        const requestBody = {
            Properties: {
                SandboxId: 'RETAIL',
                UserTokens: [xblToken]
            },
            RelyingParty: 'rp://api.minecraftservices.com/',
            TokenType: 'JWT'
        };

        const response = await this.client.post(XSTS_AUTH_URL, requestBody);
        return response.data;
    }

    async loginToMinecraft(userHash, xstsToken) {
        const requestBody = {
            identityToken: `XBL3.0 x=${userHash};${xstsToken}`
        };

        const response = await this.client.post(MC_LOGIN_URL, requestBody);
        return response.data;
    }

    async getMinecraftProfile(mcAccessToken) {
        const response = await this.client.get(PROFILE_URL, {
            headers: {
                'Authorization': `Bearer ${mcAccessToken}`
            }
        });
        return response.data;
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

async function main() {
    try {
        const authenticator = new MinecraftAuthenticator();
        const result = await authenticator.authenticate();

        console.log('\nDone!');
        console.log('You can use the following sample code to retrieve any field from the returned JSON:\n');
        console.log('const authenticator = new MinecraftAuthenticator();');
        console.log('const authResult = await authenticator.authenticate();');
        console.log('const accessToken = authResult.tokens.minecraft_access_token;');
        console.log('console.log(accessToken);\n');
        console.log('Below is the JSON returned from your recent login operation:\n');

        console.log(JSON.stringify(result, null, 2));
    } catch (error) {
        console.error('Authentication failed:', error.message);
    }
}

if (require.main === module) {
    main();
}

module.exports = MinecraftAuthenticator;