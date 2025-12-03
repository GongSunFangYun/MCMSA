// main.rs
use reqwest::blocking::Client;
use reqwest::header;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;
use warp::Filter;

const CLIENT_ID: &str = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
const REDIRECT_URI: &str = "http://localhost:3000/proxy/";
const SCOPE: &str = "XboxLive.signin offline_access";
const AUTHORIZE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const XBL_AUTH_URL: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XSTS_AUTH_URL: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";
const MC_LOGIN_URL: &str = "https://api.minecraftservices.com/authentication/login_with_xbox";
const MC_STORE_URL: &str = "https://api.minecraftservices.com/entitlements/mcstore";
const PROFILE_URL: &str = "https://api.minecraftservices.com/minecraft/profile";
const PORT: u16 = 3000;

#[derive(Debug, Serialize, Deserialize)]
struct AuthData {
    tokens: Tokens,
    profile: Value,
    pkce: PKCEData,
}

#[derive(Debug, Serialize, Deserialize)]
struct Tokens {
    microsoft_access_token: String,
    microsoft_refresh_token: String,
    xbl_token: String,
    xsts_token: String,
    minecraft_access_token: String,
    expires_in: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct PKCEData {
    code_verifier: String,
    code_challenge: String,
}

type AuthDataMap = Arc<Mutex<HashMap<String, AuthData>>>;

fn main() {
    let auth_data_map: AuthDataMap = Arc::new(Mutex::new(HashMap::new()));
    let auth_data_map_clone = auth_data_map.clone();

    println!("Server started on port: {}", PORT);
    println!("Please visit the following URL for authorization:");
    println!("{}", generate_authorize_url());
    println!("Waiting for authorization...");

    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let proxy = warp::path!("proxy")
            .and(warp::query::<HashMap<String, String>>())
            .and(warp::any().map(move || auth_data_map_clone.clone()))
            .and_then(handle_oauth_callback);

        let data = warp::path!("data" / String)
            .and(warp::any().map(move || auth_data_map.clone()))
            .and_then(handle_data_request);

        let routes = proxy.or(data);

        let (addr, server) = warp::serve(routes).bind_with_graceful_shutdown(
            ([127, 0, 0, 1], PORT),
            async {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen for ctrl+c");
            },
        );

        println!("Press Ctrl+C to exit...");
        server.await;
    });
}

fn generate_authorize_url() -> String {
    let code_challenge = generate_code_challenge();
    
    let params = [
        ("client_id", CLIENT_ID),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", SCOPE),
        ("code_challenge", &code_challenge),
        ("code_challenge_method", "S256"),
        ("prompt", "select_account"),
    ];

    let url = reqwest::Url::parse_with_params(AUTHORIZE_URL, &params).unwrap();
    url.to_string()
}

fn generate_code_challenge() -> String {
    let code_verifier = "W6i3P9qL8zX2rV5sT1uY4aB7cD0eF3gH6jK9mN2pQ5s";
    use sha2::{Sha256, Digest};
    use base64::Engine;
    
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let result = hasher.finalize();
    
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(result)
}

async fn handle_oauth_callback(
    params: HashMap<String, String>,
    auth_data_map: AuthDataMap,
) -> Result<impl warp::Reply, Infallible> {
    if let Some(auth_code) = params.get("code") {
        let auth_data_map_clone = auth_data_map.clone();
        let auth_code_clone = auth_code.clone();
        
        tokio::spawn(async move {
            handle_authentication(&auth_code_clone, auth_data_map_clone).await;
        });

        Ok(warp::reply::html("Authentication in progress... Please check console for results."))
    } else {
        Ok(warp::reply::with_status(
            "Authorization code not received",
            warp::http::StatusCode::BAD_REQUEST,
        ))
    }
}

async fn handle_data_request(
    uuid: String,
    auth_data_map: AuthDataMap,
) -> Result<impl warp::Reply, Infallible> {
    let uuid = uuid.trim_end_matches(".json").to_string();
    let map = auth_data_map.lock().unwrap();
    
    if let Some(auth_data) = map.get(&uuid) {
        let json = serde_json::to_string_pretty(auth_data).unwrap();
        Ok(warp::reply::with_header(
            json,
            "Content-Type",
            "application/json",
        ))
    } else {
        Ok(warp::reply::with_status(
            "Data not found or expired",
            warp::http::StatusCode::NOT_FOUND,
        ))
    }
}

async fn handle_authentication(auth_code: &str, auth_data_map: AuthDataMap) {
    let client = Client::new();

    println!("[1/6] Exchanging authorization code for Microsoft token...");
    let token_data = match exchange_code_for_token(&client, auth_code).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    let access_token = token_data["access_token"].as_str().unwrap();

    println!("[2/6] Xbox Live authentication...");
    let xbl_data = match authenticate_xbox_live(&client, access_token).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    let xbl_token = xbl_data["Token"].as_str().unwrap();
    let user_hash = xbl_data["DisplayClaims"]["xui"][0]["uhs"].as_str().unwrap();

    println!("[3/6] XSTS authentication...");
    let xsts_data = match authenticate_xsts(&client, xbl_token).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    let xsts_token = xsts_data["Token"].as_str().unwrap();

    println!("[4/6] Getting Minecraft access token...");
    let mc_token_data = match login_with_xbox(&client, user_hash, xsts_token).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    let mc_access_token = mc_token_data["access_token"].as_str().unwrap();

    println!("[5/6] Checking game ownership...");
    let entitlements = match check_game_ownership(&client, mc_access_token).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    if entitlements["items"].as_array().unwrap().is_empty() {
        eprintln!("Error: This account does not own Minecraft");
        return;
    }

    println!("[6/6] Getting Minecraft profile...");
    let profile = match get_minecraft_profile(&client, mc_access_token).await {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error: {}", e);
            return;
        }
    };

    let player_uuid = profile["id"].as_str().unwrap();

    let auth_data = AuthData {
        tokens: Tokens {
            microsoft_access_token: access_token.to_string(),
            microsoft_refresh_token: token_data["refresh_token"].as_str().unwrap().to_string(),
            xbl_token: xbl_token.to_string(),
            xsts_token: xsts_token.to_string(),
            minecraft_access_token: mc_access_token.to_string(),
            expires_in: token_data["expires_in"].as_i64().unwrap() as i32,
        },
        profile: profile.clone(),
        pkce: PKCEData {
            code_verifier: "W6i3P9qL8zX2rV5sT1uY4aB7cD0eF3gH6jK9mN2pQ5s".to_string(),
            code_challenge: generate_code_challenge(),
        },
    };

    {
        let mut map = auth_data_map.lock().unwrap();
        map.insert(player_uuid.to_string(), auth_data);
    }

    println!("\nDone.");
    println!("\nData access URL:");
    println!("http://localhost:{}/data/{}.json", PORT, player_uuid);
}

async fn exchange_code_for_token(client: &Client, auth_code: &str) -> Result<Value, String> {
    let params = [
        ("client_id", CLIENT_ID),
        ("code", auth_code),
        ("redirect_uri", REDIRECT_URI),
        ("grant_type", "authorization_code"),
        ("code_verifier", "W6i3P9qL8zX2rV5sT1uY4aB7cD0eF3gH6jK9mN2pQ5s"),
    ];

    let response = client
        .post(TOKEN_URL)
        .form(&params)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        response.json::<Value>().await.map_err(|e| e.to_string())
    } else {
        Err(format!("Token exchange failed: {}", response.text().await.unwrap()))
    }
}

async fn authenticate_xbox_live(client: &Client, access_token: &str) -> Result<Value, String> {
    let rps_tickets = vec![
        format!("d={}", access_token),
        access_token.to_string(),
    ];

    for rps_ticket in rps_tickets {
        let data = json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": rps_ticket
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT"
        });

        let response = client
            .post(XBL_AUTH_URL)
            .json(&data)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if response.status().is_success() {
            return response.json::<Value>().await.map_err(|e| e.to_string());
        }
    }

    Err("Xbox Live authentication failed".to_string())
}

async fn authenticate_xsts(client: &Client, xbl_token: &str) -> Result<Value, String> {
    let data = json!({
        "Properties": {
            "SandboxId": "RETAIL",
            "UserTokens": [xbl_token]
        },
        "RelyingParty": "rp://api.minecraftservices.com/",
        "TokenType": "JWT"
    });

    let response = client
        .post(XSTS_AUTH_URL)
        .json(&data)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        response.json::<Value>().await.map_err(|e| e.to_string())
    } else {
        Err(format!("XSTS authentication failed: {}", response.text().await.unwrap()))
    }
}

async fn login_with_xbox(client: &Client, user_hash: &str, xsts_token: &str) -> Result<Value, String> {
    let data = json!({
        "identityToken": format!("XBL3.0 x={};{}", user_hash, xsts_token)
    });

    let response = client
        .post(MC_LOGIN_URL)
        .json(&data)
        .header(header::CONTENT_TYPE, "application/json")
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        response.json::<Value>().await.map_err(|e| e.to_string())
    } else {
        Err(format!("Minecraft login failed: {}", response.text().await.unwrap()))
    }
}

async fn check_game_ownership(client: &Client, mc_access_token: &str) -> Result<Value, String> {
    let response = client
        .get(MC_STORE_URL)
        .header(header::AUTHORIZATION, format!("Bearer {}", mc_access_token))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        response.json::<Value>().await.map_err(|e| e.to_string())
    } else {
        Err(format!("Game ownership check failed: {}", response.text().await.unwrap()))
    }
}

async fn get_minecraft_profile(client: &Client, mc_access_token: &str) -> Result<Value, String> {
    let response = client
        .get(PROFILE_URL)
        .header(header::AUTHORIZATION, format!("Bearer {}", mc_access_token))
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if response.status().is_success() {
        response.json::<Value>().await.map_err(|e| e.to_string())
    } else {
        Err(format!("Profile fetch failed: {}", response.text().await.unwrap()))
    }
}