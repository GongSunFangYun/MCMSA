// Minecraft Authentication Script - C++ Version
// Standardized with English comments and messages
// Requires: cpp-httplib, nlohmann/json, OpenSSL

#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include "httplib.h"
#include "json.hpp"

using json = nlohmann::json;
using namespace httplib;

// Configuration
const std::string CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
const std::string REDIRECT_URI = "http://localhost:3000/proxy/";
const std::string SCOPE = "XboxLive.signin offline_access";
const int PORT = 3000;

// OAuth endpoints
const std::string AUTHORIZE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const std::string TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const std::string XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
const std::string XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
const std::string MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
const std::string MC_ENTITLEMENTS_URL = "https://api.minecraftservices.com/entitlements/mcstore";
const std::string PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

// Global state
struct AuthState {
    json auth_data;
    std::string data_endpoint;
    std::mutex mutex;
};

AuthState auth_state;
std::atomic<bool> server_running{true};

// Generate random string
std::string generate_random_string(size_t length) {
    static const char charset[] =
        "0123456789"
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    std::string result;
    result.reserve(length);

    for (size_t i = 0; i < length; i++) {
        result += charset[dis(gen)];
    }

    return result;
}

// Generate code verifier (hex string)
std::string generate_code_verifier(size_t length) {
    std::vector<unsigned char> random_bytes(length);
    RAND_bytes(random_bytes.data(), length);

    std::stringstream ss;
    for (unsigned char c : random_bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }

    std::string result = ss.str();
    if (result.length() > length) {
        result = result.substr(0, length);
    }

    return result;
}

// Base64 URL encoding
std::string base64url_encode(const std::vector<unsigned char>& data) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data.data(), data.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);

    // Convert to URL-safe base64
    for (char& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    // Remove padding
    while (!result.empty() && result.back() == '=') {
        result.pop_back();
    }

    BIO_free_all(bio);
    return result;
}

// Generate code challenge
std::string generate_code_challenge(const std::string& code_verifier) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(code_verifier.c_str()),
           code_verifier.length(), hash.data());

    return base64url_encode(hash);
}

// HTTP POST request
json http_post(const std::string& url, const std::string& data,
               const std::string& content_type, const std::string& auth_header = "") {
    Client cli(url);
    cli.set_follow_location(true);
    cli.enable_server_certificate_verification(true);
    cli.set_connection_timeout(30);
    cli.set_read_timeout(30);

    Headers headers = {{"Accept", "application/json"}};
    if (!content_type.empty()) {
        headers.emplace("Content-Type", content_type);
    }
    if (!auth_header.empty()) {
        headers.emplace("Authorization", auth_header);
    }

    auto res = cli.Post("", headers, data, content_type);
    if (res && res->status == 200) {
        try {
            return json::parse(res->body);
        } catch (const json::parse_error& e) {
            throw std::runtime_error("JSON parse error: " + std::string(e.what()));
        }
    } else {
        std::string error_msg = "HTTP POST failed: " + std::to_string(res ? res->status : 0);
        if (res && !res->body.empty()) {
            error_msg += " - " + res->body;
        }
        throw std::runtime_error(error_msg);
    }
}

// HTTP GET request
json http_get(const std::string& url, const std::string& auth_header = "") {
    Client cli(url);
    cli.set_follow_location(true);
    cli.enable_server_certificate_verification(true);
    cli.set_connection_timeout(30);
    cli.set_read_timeout(30);

    Headers headers = {{"Accept", "application/json"}};
    if (!auth_header.empty()) {
        headers.emplace("Authorization", auth_header);
    }

    auto res = cli.Get("", headers);
    if (res && res->status == 200) {
        try {
            return json::parse(res->body);
        } catch (const json::parse_error& e) {
            throw std::runtime_error("JSON parse error: " + std::string(e.what()));
        }
    } else {
        std::string error_msg = "HTTP GET failed: " + std::to_string(res ? res->status : 0);
        if (res && !res->body.empty()) {
            error_msg += " - " + res->body;
        }
        throw std::runtime_error(error_msg);
    }
}

// Exchange authorization code for tokens
json exchange_code_for_token(const std::string& auth_code, const std::string& code_verifier) {
    std::cout << "[1/6] Exchanging authorization code for Microsoft token..." << std::endl;

    std::string post_data =
        "client_id=" + CLIENT_ID + "&" +
        "code=" + auth_code + "&" +
        "redirect_uri=" + REDIRECT_URI + "&" +
        "grant_type=authorization_code&" +
        "code_verifier=" + code_verifier;

    return http_post(TOKEN_URL, post_data, "application/x-www-form-urlencoded");
}

// Xbox Live authentication
json authenticate_xbox_live(const std::string& access_token) {
    std::cout << "[2/6] Xbox Live authentication..." << std::endl;

    json data = {
        {"Properties", {
            {"AuthMethod", "RPS"},
            {"SiteName", "user.auth.xboxlive.com"},
            {"RpsTicket", "d=" + access_token}
        }},
        {"RelyingParty", "http://auth.xboxlive.com"},
        {"TokenType", "JWT"}
    };

    json result = http_post(XBL_AUTH_URL, data.dump(), "application/json");

    // Try alternative format if first fails
    if (result.contains("error")) {
        data["Properties"]["RpsTicket"] = access_token;
        result = http_post(XBL_AUTH_URL, data.dump(), "application/json");
    }

    if (result.contains("error")) {
        throw std::runtime_error("Xbox Live authentication failed");
    }

    return result;
}

// XSTS authentication
json authenticate_xsts(const std::string& xbl_token) {
    std::cout << "[3/6] XSTS authentication..." << std::endl;

    json data = {
        {"Properties", {
            {"SandboxId", "RETAIL"},
            {"UserTokens", {xbl_token}}
        }},
        {"RelyingParty", "rp://api.minecraftservices.com/"},
        {"TokenType", "JWT"}
    };

    return http_post(XSTS_AUTH_URL, data.dump(), "application/json");
}

// Login to Minecraft with Xbox
json login_with_xbox(const std::string& user_hash, const std::string& xsts_token) {
    std::cout << "[4/6] Getting Minecraft access token..." << std::endl;

    json data = {
        {"identityToken", "XBL3.0 x=" + user_hash + ";" + xsts_token}
    };

    return http_post(MC_LOGIN_URL, data.dump(), "application/json");
}

// Check Minecraft game ownership
json check_game_ownership(const std::string& mc_access_token) {
    std::cout << "[5/6] Checking game ownership..." << std::endl;

    return http_get(MC_ENTITLEMENTS_URL, "Bearer " + mc_access_token);
}

// Get Minecraft player profile
json get_minecraft_profile(const std::string& mc_access_token) {
    std::cout << "[6/6] Getting Minecraft profile..." << std::endl;

    return http_get(PROFILE_URL, "Bearer " + mc_access_token);
}

// Generate authorization URL
std::string generate_authorize_url(const std::string& code_challenge) {
    return AUTHORIZE_URL + "?" +
           "client_id=" + CLIENT_ID + "&" +
           "response_type=code&" +
           "redirect_uri=" + REDIRECT_URI + "&" +
           "scope=" + SCOPE + "&" +
           "code_challenge=" + code_challenge + "&" +
           "code_challenge_method=S256&" +
           "prompt=select_account";
}

// Open browser (cross-platform)
void open_browser(const std::string& url) {
#ifdef _WIN32
    std::string command = "start " + url;
#elif __APPLE__
    std::string command = "open \"" + url + "\"";
#else
    std::string command = "xdg-open \"" + url + "\"";
#endif

    system(command.c_str());
}

int main() {
    // Generate PKCE
    std::string code_verifier = generate_code_verifier(32);
    std::string code_challenge = generate_code_challenge(code_verifier);
    std::string auth_url = generate_authorize_url(code_challenge);

    // Create HTTP server
    Server svr;

    // Handle callback
    svr.Get("/proxy/", [&](const Request& req, Response& res) {
        auto auth_code = req.get_param_value("code");

        if (!auth_code.empty()) {
            try {
                // Authentication flow
                auto token_data = exchange_code_for_token(auth_code, code_verifier);
                std::string access_token = token_data["access_token"];

                auto xbl_data = authenticate_xbox_live(access_token);
                std::string xbl_token = xbl_data["Token"];
                std::string user_hash = xbl_data["DisplayClaims"]["xui"][0]["uhs"];

                auto xsts_data = authenticate_xsts(xbl_token);
                std::string xsts_token = xsts_data["Token"];

                auto mc_token_data = login_with_xbox(user_hash, xsts_token);
                std::string mc_access_token = mc_token_data["access_token"];

                auto entitlements = check_game_ownership(mc_access_token);
                if (entitlements["items"].empty()) {
                    throw std::runtime_error("This account does not own Minecraft");
                }

                auto profile = get_minecraft_profile(mc_access_token);
                std::string player_uuid = profile["id"];

                // Store data
                std::lock_guard<std::mutex> lock(auth_state.mutex);

                auth_state.data_endpoint = "/data/" + player_uuid + ".json";

                auth_state.auth_data = {
                    {"tokens", {
                        {"microsoft_access_token", access_token},
                        {"microsoft_refresh_token", token_data.value("refresh_token", "")},
                        {"xbl_token", xbl_token},
                        {"xsts_token", xsts_token},
                        {"minecraft_access_token", mc_access_token},
                        {"expires_in", mc_token_data.value("expires_in", 0)}
                    }},
                    {"profile", profile},
                    {"pkce", {
                        {"code_verifier", code_verifier},
                        {"code_challenge", code_challenge}
                    }}
                };

                std::cout << "\nDone." << std::endl;
                std::cout << "\nData access URL:" << std::endl;
                std::cout << "http://localhost:" << PORT << auth_state.data_endpoint << std::endl;
                std::cout << "Press Ctrl+C to exit" << std::endl;

                res.set_content("Authentication successful! Please check console for results.", "text/html");

            } catch (const std::exception& e) {
                std::cerr << "Authentication failed: " << e.what() << std::endl;
                res.status = 500;
                res.set_content("Authentication failed: " + std::string(e.what()), "text/html");
            }
        } else {
            res.status = 400;
            res.set_content("Authorization code not received", "text/html");
        }
    });

    // Handle data endpoint
    svr.Get(R"(/data/([a-f0-9-]+\.json))", [&](const Request& req, Response& res) {
        std::lock_guard<std::mutex> lock(auth_state.mutex);

        if (!auth_state.data_endpoint.empty() &&
            req.path == auth_state.data_endpoint &&
            !auth_state.auth_data.is_null()) {
            res.set_header("Content-Type", "application/json");
            res.set_content(auth_state.auth_data.dump(2), "application/json");
        } else {
            res.status = 404;
            res.set_content("Data not found or expired", "text/html");
        }
    });

    // Default route
    svr.Get("/", [&](const Request& req, Response& res) {
        res.status = 404;
        res.set_content("Not Found", "text/html");
    });

    // Start server in background thread
    std::thread server_thread([&]() {
        std::cout << "Server started on port: " << PORT << std::endl;
        std::cout << "Please visit the following URL for authorization:" << std::endl;
        std::cout << auth_url << std::endl;
        std::cout << "Waiting for authorization..." << std::endl;

        // Open browser
        open_browser(auth_url);

        svr.listen("0.0.0.0", PORT);
    });

    // Wait for Ctrl+C
    std::cout << "Press Ctrl+C to exit..." << std::endl;
    server_running = true;

    while (server_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Stop server
    svr.stop();
    server_thread.join();

    std::cout << "Exiting program" << std::endl;

    return 0;
}