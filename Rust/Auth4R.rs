use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;

const CLIENT_ID: &str = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
const SCOPE: &str = "XboxLive.signin offline_access openid profile email";

const DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const XBL_AUTH_URL: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XSTS_AUTH_URL: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";
const MC_LOGIN_URL: &str = "https://api.minecraftservices.com/authentication/login_with_xbox";
const PROFILE_URL: &str = "https://api.minecraftservices.com/minecraft/profile";

#[derive(Debug, Serialize, Deserialize)]
struct DeviceCodeResponse {
    #[serde(rename = "device_code")]
    device_code: String,
    #[serde(rename = "user_code")]
    user_code: String,
    #[serde(rename = "verification_uri")]
    verification_uri: String,
    #[serde(rename = "expires_in")]
    expires_in: i32,
    interval: i32,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "refresh_token")]
    refresh_token: String,
    #[serde(rename = "expires_in")]
    expires_in: i32,
    scope: String,
    #[serde(rename = "token_type")]
    token_type: String,
}

#[derive(Debug, Serialize)]
struct XboxAuthRequest {
    Properties: XboxAuthProperties,
    #[serde(rename = "RelyingParty")]
    relying_party: String,
    #[serde(rename = "TokenType")]
    token_type: String,
}

#[derive(Debug, Serialize)]
struct XboxAuthProperties {
    #[serde(rename = "AuthMethod")]
    auth_method: String,
    #[serde(rename = "SiteName")]
    site_name: String,
    #[serde(rename = "RpsTicket")]
    rps_ticket: String,
}

#[derive(Debug, Deserialize)]
struct XboxAuthResponse {
    #[serde(rename = "Token")]
    token: String,
    #[serde(rename = "DisplayClaims")]
    display_claims: DisplayClaims,
}

#[derive(Debug, Deserialize)]
struct DisplayClaims {
    xui: Vec<Xui>,
}

#[derive(Debug, Deserialize)]
struct Xui {
    uhs: String,
}

#[derive(Debug, Serialize)]
struct XstsAuthRequest {
    Properties: XstsAuthProperties,
    #[serde(rename = "RelyingParty")]
    relying_party: String,
    #[serde(rename = "TokenType")]
    token_type: String,
}

#[derive(Debug, Serialize)]
struct XstsAuthProperties {
    #[serde(rename = "SandboxId")]
    sandbox_id: String,
    #[serde(rename = "UserTokens")]
    user_tokens: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct XstsAuthResponse {
    #[serde(rename = "Token")]
    token: String,
}

#[derive(Debug, Serialize)]
struct MinecraftLoginRequest {
    #[serde(rename = "identityToken")]
    identity_token: String,
}

#[derive(Debug, Deserialize)]
struct MinecraftLoginResponse {
    #[serde(rename = "access_token")]
    access_token: String,
    #[serde(rename = "expires_in")]
    expires_in: i32,
}

#[derive(Debug, Deserialize)]
struct Skin {
    id: String,
    state: String,
    url: String,
    #[serde(rename = "textureKey")]
    texture_key: String,
    variant: String,
}

#[derive(Debug, Deserialize)]
struct Cape {
    id: String,
    state: String,
    url: String,
    alias: String,
}

#[derive(Debug, Deserialize)]
struct MinecraftProfile {
    id: String,
    name: String,
    skins: Vec<Skin>,
    capes: Vec<Cape>,
    #[serde(rename = "profileActions")]
    profile_actions: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize)]
struct AuthResult {
    tokens: Tokens,
    profile: MinecraftProfile,
}

#[derive(Debug, Serialize)]
struct Tokens {
    #[serde(rename = "microsoft_access_token")]
    microsoft_access_token: String,
    #[serde(rename = "microsoft_refresh_token")]
    microsoft_refresh_token: String,
    #[serde(rename = "xbl_token")]
    xbl_token: String,
    #[serde(rename = "xsts_token")]
    xsts_token: String,
    #[serde(rename = "minecraft_access_token")]
    minecraft_access_token: String,
    #[serde(rename = "expires_in")]
    expires_in: i32,
}

struct MinecraftAuthenticator {
    client: Client,
}

impl MinecraftAuthenticator {
    fn new() -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("MinecraftAuthenticator/1.0")
            .build()
            .expect("Failed to create HTTP client");
        
        Self { client }
    }

    async fn authenticate(&self) -> Result<AuthResult, Box<dyn std::error::Error>> {
        println!("Minecraft Authentication - Device Code Flow\n");

        println!("[1/6] Requesting device code...");
        let device_code_resp = self.request_device_code().await?;

        println!("\nVisit this URL: {}", device_code_resp.verification_uri);
        println!("Enter this code: {}", device_code_resp.user_code);
        println!("Waiting for authentication...");

        let token_resp = self.poll_for_token(&device_code_resp.device_code, device_code_resp.interval).await?;
        println!("\n[2/6] Polling for token...");

        let xbl_data = self.authenticate_with_xbox_live(&token_resp.access_token).await?;
        let xbl_token = xbl_data.token;
        let user_hash = &xbl_data.display_claims.xui[0].uhs;
        println!("[3/6] Xbox Live authentication...");

        let xsts_data = self.authenticate_with_xsts(&xbl_token).await?;
        let xsts_token = xsts_data.token;
        println!("[4/6] XSTS authentication...");

        let mc_token_data = self.login_to_minecraft(user_hash, &xsts_token).await?;
        let mc_access_token = mc_token_data.access_token;
        println!("[5/6] Minecraft login...");

        let profile = self.get_minecraft_profile(&mc_access_token).await?;
        println!("[6/6] Getting profile...");

        Ok(AuthResult {
            tokens: Tokens {
                microsoft_access_token: token_resp.access_token,
                microsoft_refresh_token: token_resp.refresh_token,
                xbl_token,
                xsts_token,
                minecraft_access_token: mc_access_token,
                expires_in: mc_token_data.expires_in,
            },
            profile,
        })
    }

    async fn request_device_code(&self) -> Result<DeviceCodeResponse, Box<dyn std::error::Error>> {
        let params = [
            ("client_id", CLIENT_ID),
            ("scope", SCOPE),
        ];

        let response = self.client
            .post(DEVICE_CODE_URL)
            .form(&params)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send()
            .await?;

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(format!("HTTP {}: {}", response.status(), text).into());
        }

        Ok(response.json().await?)
    }

    async fn poll_for_token(&self, device_code: &str, interval: i32) -> Result<TokenResponse, Box<dyn std::error::Error>> {
        let poll_interval = interval.max(5);
        let max_attempts = 180;

        for attempt in 0..max_attempts {
            let params = [
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", CLIENT_ID),
                ("device_code", device_code),
            ];

            let response = self.client
                .post(TOKEN_URL)
                .form(&params)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        return Ok(resp.json().await?);
                    } else {
                        let text = resp.text().await?;
                        let error_obj: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                        
                        if error_obj.get("error").and_then(|v| v.as_str()) == Some("authorization_pending") {
                            sleep(Duration::from_secs(poll_interval as u64)).await;
                            continue;
                        } else {
                            return Err(format!("Token polling error: {}", text).into());
                        }
                    }
                }
                Err(e) => {
                    if attempt == max_attempts - 1 {
                        return Err(format!("Authentication timeout - please try again: {}", e).into());
                    }
                    sleep(Duration::from_secs(poll_interval as u64)).await;
                }
            }
        }

        Err("Authentication timeout - please try again".into())
    }

    async fn authenticate_with_xbox_live(&self, access_token: &str) -> Result<XboxAuthResponse, Box<dyn std::error::Error>> {
        let attempts = vec![
            format!("d={}", access_token),
            access_token.to_string(),
        ];

        for rps_ticket in attempts {
            let request_body = XboxAuthRequest {
                Properties: XboxAuthProperties {
                    auth_method: "RPS".to_string(),
                    site_name: "user.auth.xboxlive.com".to_string(),
                    rps_ticket,
                },
                relying_party: "http://auth.xboxlive.com".to_string(),
                token_type: "JWT".to_string(),
            };

            let response = self.client
                .post(XBL_AUTH_URL)
                .json(&request_body)
                .header("Accept", "application/json")
                .send()
                .await;

            if let Ok(resp) = response {
                if resp.status().is_success() {
                    return Ok(resp.json().await?);
                }
            }
        }

        Err("Xbox Live authentication failed with both RPS ticket formats".into())
    }

    async fn authenticate_with_xsts(&self, xbl_token: &str) -> Result<XstsAuthResponse, Box<dyn std::error::Error>> {
        let request_body = XstsAuthRequest {
            Properties: XstsAuthProperties {
                sandbox_id: "RETAIL".to_string(),
                user_tokens: vec![xbl_token.to_string()],
            },
            relying_party: "rp://api.minecraftservices.com/".to_string(),
            token_type: "JWT".to_string(),
        };

        let response = self.client
            .post(XSTS_AUTH_URL)
            .json(&request_body)
            .header("Accept", "application/json")
            .send()
            .await?;

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(format!("HTTP {}: {}", response.status(), text).into());
        }

        Ok(response.json().await?)
    }

    async fn login_to_minecraft(&self, user_hash: &str, xsts_token: &str) -> Result<MinecraftLoginResponse, Box<dyn std::error::Error>> {
        let request_body = MinecraftLoginRequest {
            identity_token: format!("XBL3.0 x={};{}", user_hash, xsts_token),
        };

        let response = self.client
            .post(MC_LOGIN_URL)
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(format!("HTTP {}: {}", response.status(), text).into());
        }

        Ok(response.json().await?)
    }

    async fn get_minecraft_profile(&self, mc_access_token: &str) -> Result<MinecraftProfile, Box<dyn std::error::Error>> {
        let response = self.client
            .get(PROFILE_URL)
            .header("Authorization", format!("Bearer {}", mc_access_token))
            .send()
            .await?;

        if !response.status().is_success() {
            let text = response.text().await?;
            return Err(format!("HTTP {}: {}", response.status(), text).into());
        }

        Ok(response.json().await?)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let authenticator = MinecraftAuthenticator::new();
    
    match authenticator.authenticate().await {
        Ok(result) => {
            println!("\nDone!");
            println!("You can use the following sample code to retrieve any field from the returned JSON:\n");
            println!("let authenticator = MinecraftAuthenticator::new();");
            println!("let result = authenticator.authenticate().await?;");
            println!("let access_token = result.tokens.minecraft_access_token;");
            println!("println!(\"{{}}\", access_token);\n");
            println!("Below is the JSON returned from your recent login operation:\n");
            
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Err(e) => {
            eprintln!("Authentication failed: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}