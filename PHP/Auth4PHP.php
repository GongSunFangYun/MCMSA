<?php

class Auth4PHP {
    private const CLIENT_ID = '4a07b708-b86d-4365-a55f-f4f23ecb85ab';
    private const SCOPE = 'XboxLive.signin offline_access openid profile email';

    private const DEVICE_CODE_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode';
    private const TOKEN_URL = 'https://login.microsoftonline.com/consumers/oauth2/v2.0/token';
    private const XBL_AUTH_URL = 'https://user.auth.xboxlive.com/user/authenticate';
    private const XSTS_AUTH_URL = 'https://xsts.auth.xboxlive.com/xsts/authorize';
    private const MC_LOGIN_URL = 'https://api.minecraftservices.com/authentication/login_with_xbox';
    private const PROFILE_URL = 'https://api.minecraftservices.com/minecraft/profile';

    private $httpClient;

    public function __construct() {
        $this->httpClient = new \GuzzleHttp\Client([
            'timeout' => 30,
            'headers' => [
                'User-Agent' => 'MinecraftAuthenticator/1.0'
            ]
        ]);
    }

    public function authenticate() {
        echo "Minecraft Authentication - Device Code Flow\n\n";

        try {
            echo "[1/6] Requesting device code...\n";
            $deviceCodeResponse = $this->requestDeviceCode();

            echo "\nVisit this URL: " . $deviceCodeResponse['verification_uri'] . "\n";
            echo "Enter this code: " . $deviceCodeResponse['user_code'] . "\n";
            echo "Waiting for authentication...\n";

            $tokenResponse = $this->pollForToken($deviceCodeResponse['device_code'], $deviceCodeResponse['interval']);
            echo "\n[2/6] Polling for token...\n";

            $xblData = $this->authenticateWithXboxLive($tokenResponse['access_token']);
            $xblToken = $xblData['Token'];
            $userHash = $xblData['DisplayClaims']['xui'][0]['uhs'];
            echo "[3/6] Xbox Live authentication...\n";

            $xstsData = $this->authenticateWithXSTS($xblToken);
            $xstsToken = $xstsData['Token'];
            echo "[4/6] XSTS authentication...\n";

            $mcTokenData = $this->loginToMinecraft($userHash, $xstsToken);
            $mcAccessToken = $mcTokenData['access_token'];
            echo "[5/6] Minecraft login...\n";

            $profile = $this->getMinecraftProfile($mcAccessToken);
            echo "[6/6] Getting profile...\n";

            return [
                'tokens' => [
                    'microsoft_access_token' => $tokenResponse['access_token'],
                    'microsoft_refresh_token' => $tokenResponse['refresh_token'],
                    'xbl_token' => $xblToken,
                    'xsts_token' => $xstsToken,
                    'minecraft_access_token' => $mcAccessToken,
                    'expires_in' => $mcTokenData['expires_in']
                ],
                'profile' => $profile
            ];

        } catch (Exception $e) {
            echo "Authentication failed: " . $e->getMessage() . "\n";
            throw $e;
        }
    }

    private function requestDeviceCode() {
        $response = $this->httpClient->post(self::DEVICE_CODE_URL, [
            'form_params' => [
                'client_id' => self::CLIENT_ID,
                'scope' => self::SCOPE
            ],
            'headers' => [
                'Content-Type' => 'application/x-www-form-urlencoded'
            ]
        ]);

        return json_decode($response->getBody(), true);
    }

    private function pollForToken($deviceCode, $interval) {
        $pollInterval = max($interval, 5);
        $maxAttempts = 180;

        for ($attempt = 0; $attempt < $maxAttempts; $attempt++) {
            try {
                $response = $this->httpClient->post(self::TOKEN_URL, [
                    'form_params' => [
                        'grant_type' => 'urn:ietf:params:oauth:grant-type:device_code',
                        'client_id' => self::CLIENT_ID,
                        'device_code' => $deviceCode
                    ],
                    'headers' => [
                        'Content-Type' => 'application/x-www-form-urlencoded'
                    ]
                ]);

                return json_decode($response->getBody(), true);
            } catch (\GuzzleHttp\Exception\ClientException $e) {
                $errorResponse = json_decode($e->getResponse()->getBody(), true);
                
                if (isset($errorResponse['error']) && $errorResponse['error'] === 'authorization_pending') {
                    sleep($pollInterval);
                    continue;
                } else {
                    throw new Exception("Token polling error: " . json_encode($errorResponse));
                }
            } catch (Exception $e) {
                if ($attempt === $maxAttempts - 1) {
                    throw new Exception("Authentication timeout - please try again", 0, $e);
                }
                sleep($pollInterval);
            }
        }

        throw new Exception("Authentication timeout - please try again");
    }

    private function authenticateWithXboxLive($accessToken) {
        $attempts = ["d=" . $accessToken, $accessToken];

        foreach ($attempts as $rpsTicket) {
            try {
                $requestBody = [
                    'Properties' => [
                        'AuthMethod' => 'RPS',
                        'SiteName' => 'user.auth.xboxlive.com',
                        'RpsTicket' => $rpsTicket
                    ],
                    'RelyingParty' => 'http://auth.xboxlive.com',
                    'TokenType' => 'JWT'
                ];

                $response = $this->httpClient->post(self::XBL_AUTH_URL, [
                    'json' => $requestBody,
                    'headers' => [
                        'Accept' => 'application/json'
                    ]
                ]);

                return json_decode($response->getBody(), true);
            } catch (Exception $e) {
                continue;
            }
        }

        throw new Exception("Xbox Live authentication failed with both RPS ticket formats");
    }

    private function authenticateWithXSTS($xblToken) {
        $requestBody = [
            'Properties' => [
                'SandboxId' => 'RETAIL',
                'UserTokens' => [$xblToken]
            ],
            'RelyingParty' => 'rp://api.minecraftservices.com/',
            'TokenType' => 'JWT'
        ];

        $response = $this->httpClient->post(self::XSTS_AUTH_URL, [
            'json' => $requestBody,
            'headers' => [
                'Accept' => 'application/json'
            ]
        ]);

        return json_decode($response->getBody(), true);
    }

    private function loginToMinecraft($userHash, $xstsToken) {
        $requestBody = [
            'identityToken' => "XBL3.0 x=$userHash;$xstsToken"
        ];

        $response = $this->httpClient->post(self::MC_LOGIN_URL, [
            'json' => $requestBody
        ]);

        return json_decode($response->getBody(), true);
    }

    private function getMinecraftProfile($mcAccessToken) {
        $response = $this->httpClient->get(self::PROFILE_URL, [
            'headers' => [
                'Authorization' => "Bearer $mcAccessToken"
            ]
        ]);

        return json_decode($response->getBody(), true);
    }
}

try {
    $authenticator = new Auth4PHP();
    $result = $authenticator->authenticate();

    echo "\nDone!\n";
    echo "You can use the following sample code to retrieve any field from the returned JSON:\n\n";
    echo "\$authenticator = new Auth4PHP();\n";
    echo "\$result = \$authenticator->authenticate();\n";
    echo "\$accessToken = \$result['tokens']['minecraft_access_token'];\n";
    echo "echo \$accessToken;\n\n";
    echo "Below is the JSON returned from your recent login operation:\n\n";

    echo json_encode($result, JSON_PRETTY_PRINT) . "\n";
} catch (Exception $e) {
    echo "Authentication failed: " . $e->getMessage() . "\n";
}