#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;

const string CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
const string SCOPE = "XboxLive.signin offline_access openid profile email";

const string DEVICE_CODE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const string TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const string XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
const string XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
const string MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
const string PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

struct DeviceCodeResponse {
    string device_code;
    string user_code;
    string verification_uri;
    int expires_in;
    int interval;
    string message;
};

struct TokenResponse {
    string access_token;
    string refresh_token;
    int expires_in;
    string scope;
    string token_type;
};

struct XboxAuthResponse {
    string Token;
    struct DisplayClaims {
        struct Xui {
            string uhs;
        };
        vector<Xui> xui;
    } DisplayClaims;
};

struct XstsAuthResponse {
    string Token;
};

struct MinecraftLoginResponse {
    string access_token;
    int expires_in;
};

struct Skin {
    string id;
    string state;
    string url;
    string textureKey;
    string variant;
};

struct Cape {
    string id;
    string state;
    string url;
    string alias;
};

struct MinecraftProfile {
    string id;
    string name;
    vector<Skin> skins;
    vector<Cape> capes;
    map<string, string> profileActions;
};

struct AuthResult {
    struct Tokens {
        string microsoft_access_token;
        string microsoft_refresh_token;
        string xbl_token;
        string xsts_token;
        string minecraft_access_token;
        int expires_in;
    } tokens;
    MinecraftProfile profile;
};

class HttpRequest {
public:
    static string PostForm(const string& url, const map<string, string>& params) {
        string postFields;
        for (const auto& [key, value] : params) {
            if (!postFields.empty()) postFields += "&";
            postFields += key + "=" + EscapeUrl(value);
        }
        
        return Request("POST", url, {{"Content-Type", "application/x-www-form-urlencoded"}}, postFields);
    }
    
    static string PostJson(const string& url, const json& data, const map<string, string>& headers = {}) {
        auto allHeaders = headers;
        allHeaders["Content-Type"] = "application/json";
        allHeaders["Accept"] = "application/json";
        
        return Request("POST", url, allHeaders, data.dump());
    }
    
    static string Get(const string& url, const map<string, string>& headers = {}) {
        return Request("GET", url, headers, "");
    }
    
private:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, string* userp) {
        size_t totalSize = size * nmemb;
        userp->append((char*)contents, totalSize);
        return totalSize;
    }
    
    static string EscapeUrl(const string& value) {
        CURL* curl = curl_easy_init();
        char* escaped = curl_easy_escape(curl, value.c_str(), value.length());
        string result(escaped);
        curl_free(escaped);
        curl_easy_cleanup(curl);
        return result;
    }
    
    static string Request(const string& method, const string& url, 
                         const map<string, string>& headers, const string& body) {
        CURL* curl = curl_easy_init();
        if (!curl) throw runtime_error("Failed to initialize curl");
        
        struct curl_slist* headerList = nullptr;
        for (const auto& [key, value] : headers) {
            headerList = curl_slist_append(headerList, (key + ": " + value).c_str());
        }
        
        string response;
        long httpCode = 0;
        
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "MinecraftAuthenticator/1.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        
        if (!body.empty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        }
        
        CURLcode res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        
        curl_slist_free_all(headerList);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK) {
            throw runtime_error("Curl error: " + string(curl_easy_strerror(res)));
        }
        
        if (httpCode != 200) {
            throw runtime_error("HTTP " + to_string(httpCode) + ": " + response);
        }
        
        return response;
    }
};

class MinecraftAuthenticator {
public:
    MinecraftAuthenticator() {
        curl_global_init(CURL_GLOBAL_ALL);
    }
    
    ~MinecraftAuthenticator() {
        curl_global_cleanup();
    }
    
    AuthResult authenticate() {
        cout << "Minecraft Authentication - Device Code Flow\n" << endl;
        
        try {
            cout << "[1/6] Requesting device code..." << endl;
            auto deviceCodeResponse = requestDeviceCode();
            
            cout << "\nVisit this URL: " << deviceCodeResponse.verification_uri << endl;
            cout << "Enter this code: " << deviceCodeResponse.user_code << endl;
            cout << "Waiting for authentication..." << endl;
            
            auto tokenResponse = pollForToken(deviceCodeResponse.device_code, deviceCodeResponse.interval);
            cout << "\n[2/6] Polling for token..." << endl;
            
            auto xblData = authenticateWithXboxLive(tokenResponse.access_token);
            string xblToken = xblData.Token;
            string userHash = xblData.DisplayClaims.xui[0].uhs;
            cout << "[3/6] Xbox Live authentication..." << endl;
            
            auto xstsData = authenticateWithXSTS(xblToken);
            string xstsToken = xstsData.Token;
            cout << "[4/6] XSTS authentication..." << endl;
            
            auto mcTokenData = loginToMinecraft(userHash, xstsToken);
            string mcAccessToken = mcTokenData.access_token;
            cout << "[5/6] Minecraft login..." << endl;
            
            auto profile = getMinecraftProfile(mcAccessToken);
            cout << "[6/6] Getting profile..." << endl;
            
            return {
                .tokens = {
                    .microsoft_access_token = tokenResponse.access_token,
                    .microsoft_refresh_token = tokenResponse.refresh_token,
                    .xbl_token = xblToken,
                    .xsts_token = xstsToken,
                    .minecraft_access_token = mcAccessToken,
                    .expires_in = mcTokenData.expires_in
                },
                .profile = profile
            };
            
        } catch (const exception& e) {
            cout << "Authentication failed: " << e.what() << endl;
            throw;
        }
    }
    
private:
    DeviceCodeResponse requestDeviceCode() {
        map<string, string> params = {
            {"client_id", CLIENT_ID},
            {"scope", SCOPE}
        };
        
        string response = HttpRequest::PostForm(DEVICE_CODE_URL, params);
        json j = json::parse(response);
        
        return {
            .device_code = j["device_code"],
            .user_code = j["user_code"],
            .verification_uri = j["verification_uri"],
            .expires_in = j["expires_in"],
            .interval = j["interval"],
            .message = j["message"]
        };
    }
    
    TokenResponse pollForToken(const string& deviceCode, int interval) {
        int pollInterval = max(interval, 5);
        int maxAttempts = 180;
        
        for (int attempt = 0; attempt < maxAttempts; attempt++) {
            try {
                map<string, string> params = {
                    {"grant_type", "urn:ietf:params:oauth:grant-type:device_code"},
                    {"client_id", CLIENT_ID},
                    {"device_code", deviceCode}
                };
                
                string response = HttpRequest::PostForm(TOKEN_URL, params);
                json j = json::parse(response);
                
                return {
                    .access_token = j["access_token"],
                    .refresh_token = j["refresh_token"],
                    .expires_in = j["expires_in"],
                    .scope = j["scope"],
                    .token_type = j["token_type"]
                };
                
            } catch (const exception& e) {
                string errorMsg = e.what();
                if (errorMsg.find("authorization_pending") != string::npos) {
                    this_thread::sleep_for(chrono::seconds(pollInterval));
                    continue;
                }
                
                if (attempt == maxAttempts - 1) {
                    throw runtime_error("Authentication timeout - please try again");
                }
                
                this_thread::sleep_for(chrono::seconds(pollInterval));
            }
        }
        
        throw runtime_error("Authentication timeout - please try again");
    }
    
    XboxAuthResponse authenticateWithXboxLive(const string& accessToken) {
        vector<string> attempts = {"d=" + accessToken, accessToken};
        
        for (const auto& rpsTicket : attempts) {
            try {
                json requestBody = {
                    {"Properties", {
                        {"AuthMethod", "RPS"},
                        {"SiteName", "user.auth.xboxlive.com"},
                        {"RpsTicket", rpsTicket}
                    }},
                    {"RelyingParty", "http://auth.xboxlive.com"},
                    {"TokenType", "JWT"}
                };
                
                string response = HttpRequest::PostJson(XBL_AUTH_URL, requestBody);
                json j = json::parse(response);
                
                XboxAuthResponse result;
                result.Token = j["Token"];
                
                for (const auto& xui : j["DisplayClaims"]["xui"]) {
                    result.DisplayClaims.xui.push_back({.uhs = xui["uhs"]});
                }
                
                return result;
                
            } catch (...) {
                continue;
            }
        }
        
        throw runtime_error("Xbox Live authentication failed with both RPS ticket formats");
    }
    
    XstsAuthResponse authenticateWithXSTS(const string& xblToken) {
        json requestBody = {
            {"Properties", {
                {"SandboxId", "RETAIL"},
                {"UserTokens", {xblToken}}
            }},
            {"RelyingParty", "rp://api.minecraftservices.com/"},
            {"TokenType", "JWT"}
        };
        
        string response = HttpRequest::PostJson(XSTS_AUTH_URL, requestBody);
        json j = json::parse(response);
        
        return {.Token = j["Token"]};
    }
    
    MinecraftLoginResponse loginToMinecraft(const string& userHash, const string& xstsToken) {
        json requestBody = {
            {"identityToken", "XBL3.0 x=" + userHash + ";" + xstsToken}
        };
        
        string response = HttpRequest::PostJson(MC_LOGIN_URL, requestBody);
        json j = json::parse(response);
        
        return {
            .access_token = j["access_token"],
            .expires_in = j["expires_in"]
        };
    }
    
    MinecraftProfile getMinecraftProfile(const string& mcAccessToken) {
        map<string, string> headers = {
            {"Authorization", "Bearer " + mcAccessToken}
        };
        
        string response = HttpRequest::Get(PROFILE_URL, headers);
        json j = json::parse(response);
        
        MinecraftProfile profile;
        profile.id = j["id"];
        profile.name = j["name"];
        
        if (j.contains("skins")) {
            for (const auto& skin : j["skins"]) {
                profile.skins.push_back({
                    .id = skin["id"],
                    .state = skin["state"],
                    .url = skin["url"],
                    .textureKey = skin["textureKey"],
                    .variant = skin["variant"]
                });
            }
        }
        
        if (j.contains("capes")) {
            for (const auto& cape : j["capes"]) {
                profile.capes.push_back({
                    .id = cape["id"],
                    .state = cape["state"],
                    .url = cape["url"],
                    .alias = cape["alias"]
                });
            }
        }
        
        if (j.contains("profileActions")) {
            for (auto& [key, value] : j["profileActions"].items()) {
                profile.profileActions[key] = value;
            }
        }
        
        return profile;
    }
};

int main() {
    try {
        MinecraftAuthenticator authenticator;
        AuthResult result = authenticator.authenticate();
        
        cout << "\nDone!" << endl;
        cout << "You can use the following sample code to retrieve any field from the returned JSON:\n" << endl;
        cout << "MinecraftAuthenticator authenticator;" << endl;
        cout << "AuthResult result = authenticator.authenticate();" << endl;
        cout << "string accessToken = result.tokens.minecraft_access_token;" << endl;
        cout << "cout << accessToken << endl;\n" << endl;
        cout << "Below is the JSON returned from your recent login operation:\n" << endl;
        
        json output = {
            {"tokens", {
                {"microsoft_access_token", result.tokens.microsoft_access_token},
                {"microsoft_refresh_token", result.tokens.microsoft_refresh_token},
                {"xbl_token", result.tokens.xbl_token},
                {"xsts_token", result.tokens.xsts_token},
                {"minecraft_access_token", result.tokens.minecraft_access_token},
                {"expires_in", result.tokens.expires_in}
            }},
            {"profile", {
                {"id", result.profile.id},
                {"name", result.profile.name}
            }}
        };
        
        cout << output.dump(2) << endl;
        
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}