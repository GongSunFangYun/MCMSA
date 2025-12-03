/* Minecraft Authentication Script - C Version
 * Standardized with English comments and messages
 * Requires: libcurl, libmicrohttpd, jansson, openssl
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <curl/curl.h>
#include <microhttpd.h>
#include <jansson.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Configuration
#define CLIENT_ID "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
#define REDIRECT_URI "http://localhost:3000/proxy/"
#define SCOPE "XboxLive.signin offline_access"
#define PORT 3000

// OAuth endpoints
#define AUTHORIZE_URL "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
#define TOKEN_URL "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
#define XBL_AUTH_URL "https://user.auth.xboxlive.com/user/authenticate"
#define XSTS_AUTH_URL "https://xsts.auth.xboxlive.com/xsts/authorize"
#define MC_LOGIN_URL "https://api.minecraftservices.com/authentication/login_with_xbox"
#define MC_ENTITLEMENTS_URL "https://api.minecraftservices.com/entitlements/mcstore"
#define PROFILE_URL "https://api.minecraftservices.com/minecraft/profile"

// Global state
typedef struct {
    json_t *auth_data;
    char *data_endpoint;
    pthread_mutex_t mutex;
} AuthState;

AuthState auth_state = {0};
volatile int server_running = 1;

// Base64 URL encoding
char *base64url_encode(const unsigned char *data, size_t input_length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, input_length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    char *b64text = (char *)malloc(bufferPtr->length + 1);
    memcpy(b64text, bufferPtr->data, bufferPtr->length);
    b64text[bufferPtr->length] = '\0';

    // Convert to URL-safe base64
    for (size_t i = 0; i < bufferPtr->length; i++) {
        if (b64text[i] == '+') b64text[i] = '-';
        else if (b64text[i] == '/') b64text[i] = '_';
        else if (b64text[i] == '=') {
            b64text[i] = '\0';
            break;
        }
    }

    BIO_free_all(bio);
    return b64text;
}

// Generate random string
char *generate_random_string(size_t length) {
    unsigned char *random_bytes = malloc(length);
    if (!random_bytes) return NULL;

    if (RAND_bytes(random_bytes, length) != 1) {
        free(random_bytes);
        return NULL;
    }

    char *hex_string = malloc(length * 2 + 1);
    if (!hex_string) {
        free(random_bytes);
        return NULL;
    }

    for (size_t i = 0; i < length; i++) {
        sprintf(hex_string + i * 2, "%02x", random_bytes[i]);
    }
    hex_string[length * 2] = '\0';

    free(random_bytes);
    return hex_string;
}

// Generate code challenge
char *generate_code_challenge(const char *code_verifier) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)code_verifier, strlen(code_verifier), hash);
    return base64url_encode(hash, SHA256_DIGEST_LENGTH);
}

// cURL write callback
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    char **response_ptr = (char **)userdata;

    *response_ptr = realloc(*response_ptr, strlen(*response_ptr ? *response_ptr : "") + total_size + 1);
    if (*response_ptr == NULL) return 0;

    strncat(*response_ptr, (char *)ptr, total_size);
    return total_size;
}

// HTTP POST request
json_t *http_post(const char *url, const char *data, const char *content_type, const char *auth_header) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    json_t *json = NULL;
    json_error_t error;

    curl = curl_easy_init();
    if (!curl) return NULL;

    struct curl_slist *headers = NULL;
    if (content_type) {
        char content_type_header[256];
        snprintf(content_type_header, sizeof(content_type_header), "Content-Type: %s", content_type);
        headers = curl_slist_append(headers, content_type_header);
    }
    if (auth_header) {
        headers = curl_slist_append(headers, auth_header);
    }
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && response) {
        json = json_loads(response, 0, &error);
    } else {
        fprintf(stderr, "cURL request failed: %s\n", curl_easy_strerror(res));
    }

    if (headers) curl_slist_free_all(headers);
    if (response) free(response);
    curl_easy_cleanup(curl);

    return json;
}

// HTTP GET request
json_t *http_get(const char *url, const char *auth_header) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    json_t *json = NULL;
    json_error_t error;

    curl = curl_easy_init();
    if (!curl) return NULL;

    struct curl_slist *headers = NULL;
    if (auth_header) {
        headers = curl_slist_append(headers, auth_header);
    }
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK && response) {
        json = json_loads(response, 0, &error);
    } else {
        fprintf(stderr, "cURL request failed: %s\n", curl_easy_strerror(res));
    }

    if (headers) curl_slist_free_all(headers);
    if (response) free(response);
    curl_easy_cleanup(curl);

    return json;
}

// Exchange authorization code for tokens
json_t *exchange_code_for_token(const char *auth_code, const char *code_verifier) {
    char post_data[2048];
    snprintf(post_data, sizeof(post_data),
             "client_id=%s&code=%s&redirect_uri=%s&grant_type=authorization_code&code_verifier=%s",
             CLIENT_ID, auth_code, REDIRECT_URI, code_verifier);

    printf("[1/6] Exchanging authorization code for Microsoft token...\n");
    return http_post(TOKEN_URL, post_data, "application/x-www-form-urlencoded", NULL);
}

// Xbox Live authentication
json_t *authenticate_xbox_live(const char *access_token) {
    json_t *root = json_object();
    json_t *properties = json_object();

    json_object_set(properties, "AuthMethod", json_string("RPS"));
    json_object_set(properties, "SiteName", json_string("user.auth.xboxlive.com"));
    json_object_set(properties, "RpsTicket", json_string(access_token));

    json_object_set(root, "Properties", properties);
    json_object_set(root, "RelyingParty", json_string("http://auth.xboxlive.com"));
    json_object_set(root, "TokenType", json_string("JWT"));

    char *data = json_dumps(root, 0);
    json_t *result = http_post(XBL_AUTH_URL, data, "application/json", NULL);

    free(data);
    json_decref(root);
    return result;
}

// XSTS authentication
json_t *authenticate_xsts(const char *xbl_token) {
    json_t *root = json_object();
    json_t *properties = json_object();
    json_t *user_tokens = json_array();

    json_array_append(user_tokens, json_string(xbl_token));
    json_object_set(properties, "SandboxId", json_string("RETAIL"));
    json_object_set(properties, "UserTokens", user_tokens);

    json_object_set(root, "Properties", properties);
    json_object_set(root, "RelyingParty", json_string("rp://api.minecraftservices.com/"));
    json_object_set(root, "TokenType", json_string("JWT"));

    char *data = json_dumps(root, 0);
    json_t *result = http_post(XSTS_AUTH_URL, data, "application/json", NULL);

    free(data);
    json_decref(root);
    return result;
}

// Login to Minecraft with Xbox
json_t *login_with_xbox(const char *user_hash, const char *xsts_token) {
    json_t *root = json_object();
    char identity_token[512];

    snprintf(identity_token, sizeof(identity_token), "XBL3.0 x=%s;%s", user_hash, xsts_token);
    json_object_set(root, "identityToken", json_string(identity_token));

    char *data = json_dumps(root, 0);
    json_t *result = http_post(MC_LOGIN_URL, data, "application/json", NULL);

    free(data);
    json_decref(root);
    return result;
}

// Check Minecraft game ownership
json_t *check_game_ownership(const char *mc_access_token) {
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", mc_access_token);
    return http_get(MC_ENTITLEMENTS_URL, auth_header);
}

// Get Minecraft player profile
json_t *get_minecraft_profile(const char *mc_access_token) {
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", mc_access_token);
    return http_get(PROFILE_URL, auth_header);
}

// Generate authorization URL
char *generate_authorize_url(const char *code_challenge) {
    char *url = malloc(1024);
    snprintf(url, 1024,
             "%s?client_id=%s&response_type=code&redirect_uri=%s&scope=%s"
             "&code_challenge=%s&code_challenge_method=S256&prompt=select_account",
             AUTHORIZE_URL, CLIENT_ID, REDIRECT_URI, SCOPE, code_challenge);
    return url;
}

// MicroHTTPD request handler
enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                                const char *url, const char *method,
                                const char *version, const char *upload_data,
                                size_t *upload_data_size, void **con_cls) {

    if (strcmp(method, "GET") != 0) {
        return MHD_NO;
    }

    // Handle callback
    if (strncmp(url, "/proxy/", 7) == 0) {
        const char *query = strchr(url, '?');
        if (query) {
            char *auth_code = NULL;
            char *key = NULL;
            char *value = NULL;
            char *query_copy = strdup(query + 1);
            char *token = strtok(query_copy, "&");

            while (token) {
                key = strtok(token, "=");
                value = strtok(NULL, "=");
                if (key && value && strcmp(key, "code") == 0) {
                    auth_code = strdup(value);
                    break;
                }
                token = strtok(NULL, "&");
            }

            free(query_copy);

            if (auth_code) {
                // Generate PKCE
                char *code_verifier = generate_random_string(32);
                char *code_challenge = generate_code_challenge(code_verifier);

                // Authentication flow
                json_t *token_data = exchange_code_for_token(auth_code, code_verifier);
                if (!token_data) {
                    free(auth_code);
                    free(code_verifier);
                    free(code_challenge);
                    const char *error = "Authentication failed at step 1";
                    struct MHD_Response *response = MHD_create_response_from_buffer(
                        strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
                    return MHD_queue_response(connection, 500, response);
                }

                const char *access_token = json_string_value(json_object_get(token_data, "access_token"));
                printf("[2/6] Xbox Live authentication...\n");
                json_t *xbl_data = authenticate_xbox_live(access_token);
                if (!xbl_data) {
                    json_decref(token_data);
                    free(auth_code);
                    free(code_verifier);
                    free(code_challenge);
                    const char *error = "Authentication failed at step 2";
                    struct MHD_Response *response = MHD_create_response_from_buffer(
                        strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
                    return MHD_queue_response(connection, 500, response);
                }

                json_t *display_claims = json_object_get(xbl_data, "DisplayClaims");
                json_t *xui = json_object_get(display_claims, "xui");
                json_t *xui0 = json_array_get(xui, 0);
                const char *user_hash = json_string_value(json_object_get(xui0, "uhs"));
                const char *xbl_token = json_string_value(json_object_get(xbl_data, "Token"));

                printf("[3/6] XSTS authentication...\n");
                json_t *xsts_data = authenticate_xsts(xbl_token);
                if (!xsts_data) {
                    json_decref(token_data);
                    json_decref(xbl_data);
                    free(auth_code);
                    free(code_verifier);
                    free(code_challenge);
                    const char *error = "Authentication failed at step 3";
                    struct MHD_Response *response = MHD_create_response_from_buffer(
                        strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
                    return MHD_queue_response(connection, 500, response);
                }

                const char *xsts_token = json_string_value(json_object_get(xsts_data, "Token"));

                printf("[4/6] Getting Minecraft access token...\n");
                json_t *mc_token_data = login_with_xbox(user_hash, xsts_token);
                if (!mc_token_data) {
                    json_decref(token_data);
                    json_decref(xbl_data);
                    json_decref(xsts_data);
                    free(auth_code);
                    free(code_verifier);
                    free(code_challenge);
                    const char *error = "Authentication failed at step 4";
                    struct MHD_Response *response = MHD_create_response_from_buffer(
                        strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
                    return MHD_queue_response(connection, 500, response);
                }

                const char *mc_access_token = json_string_value(json_object_get(mc_token_data, "access_token"));

                printf("[5/6] Checking game ownership...\n");
                json_t *entitlements = check_game_ownership(mc_access_token);
                if (!entitlements) {
                    json_decref(token_data);
                    json_decref(xbl_data);
                    json_decref(xsts_data);
                    json_decref(mc_token_data);
                    free(auth_code);
                    free(code_verifier);
                    free(code_challenge);
                    const char *error = "Authentication failed at step 5";
                    struct MHD_Response *response = MHD_create_response_from_buffer(
                        strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
                    return MHD_queue_response(connection, 500, response);
                }

                json_t *items = json_object_get(entitlements, "items");
                if (json_array_size(items) == 0) {
                    const char *error = "This account does not own Minecraft";
                    struct MHD_Response *response = MHD_create_response_from_buffer(
                        strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
                    return MHD_queue_response(connection, 500, response);
                }

                printf("[6/6] Getting Minecraft profile...\n");
                json_t *profile = get_minecraft_profile(mc_access_token);
                if (!profile) {
                    json_decref(token_data);
                    json_decref(xbl_data);
                    json_decref(xsts_data);
                    json_decref(mc_token_data);
                    json_decref(entitlements);
                    free(auth_code);
                    free(code_verifier);
                    free(code_challenge);
                    const char *error = "Authentication failed at step 6";
                    struct MHD_Response *response = MHD_create_response_from_buffer(
                        strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
                    return MHD_queue_response(connection, 500, response);
                }

                // Create auth data
                pthread_mutex_lock(&auth_state.mutex);

                if (auth_state.auth_data) {
                    json_decref(auth_state.auth_data);
                }
                if (auth_state.data_endpoint) {
                    free(auth_state.data_endpoint);
                }

                // Build auth_data JSON
                auth_state.auth_data = json_object();
                json_t *tokens = json_object();
                json_t *pkce = json_object();

                const char *player_uuid = json_string_value(json_object_get(profile, "id"));
                auth_state.data_endpoint = malloc(256);
                snprintf(auth_state.data_endpoint, 256, "/data/%s.json", player_uuid);

                json_object_set(tokens, "microsoft_access_token", json_string(access_token));
                json_object_set(tokens, "microsoft_refresh_token",
                               json_string(json_string_value(json_object_get(token_data, "refresh_token"))));
                json_object_set(tokens, "xbl_token", json_string(xbl_token));
                json_object_set(tokens, "xsts_token", json_string(xsts_token));
                json_object_set(tokens, "minecraft_access_token", json_string(mc_access_token));
                json_object_set(tokens, "expires_in",
                               json_integer(json_integer_value(json_object_get(mc_token_data, "expires_in"))));

                json_object_set(pkce, "code_verifier", json_string(code_verifier));
                json_object_set(pkce, "code_challenge", json_string(code_challenge));

                json_object_set(auth_state.auth_data, "tokens", tokens);
                json_object_set(auth_state.auth_data, "profile", json_incref(profile));
                json_object_set(auth_state.auth_data, "pkce", pkce);

                pthread_mutex_unlock(&auth_state.mutex);

                printf("\nDone.\n");
                printf("\nData access URL:\n");
                printf("http://localhost:%d%s\n", PORT, auth_state.data_endpoint);
                printf("Press Ctrl+C to exit\n");

                // Cleanup
                free(auth_code);
                free(code_verifier);
                free(code_challenge);
                json_decref(token_data);
                json_decref(xbl_data);
                json_decref(xsts_data);
                json_decref(mc_token_data);
                json_decref(entitlements);
                json_decref(profile);

                const char *success = "Authentication successful! Please check console for results.";
                struct MHD_Response *response = MHD_create_response_from_buffer(
                    strlen(success), (void *)success, MHD_RESPMEM_PERSISTENT);
                return MHD_queue_response(connection, 200, response);
            }
        }

        const char *error = "Authorization code not received";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(error), (void *)error, MHD_RESPMEM_PERSISTENT);
        return MHD_queue_response(connection, 400, response);
    }

    // Handle data endpoint
    pthread_mutex_lock(&auth_state.mutex);
    if (auth_state.data_endpoint && strcmp(url, auth_state.data_endpoint) == 0 && auth_state.auth_data) {
        char *data = json_dumps(auth_state.auth_data, JSON_INDENT(2));
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(data), data, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(response, "Content-Type", "application/json");
        pthread_mutex_unlock(&auth_state.mutex);
        return MHD_queue_response(connection, 200, response);
    }
    pthread_mutex_unlock(&auth_state.mutex);

    const char *not_found = "Not Found";
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(not_found), (void *)not_found, MHD_RESPMEM_PERSISTENT);
    return MHD_queue_response(connection, 404, response);
}

// Signal handler
void signal_handler(int sig) {
    server_running = 0;
}

int main() {
    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize mutex
    pthread_mutex_init(&auth_state.mutex, NULL);

    // Initialize OpenSSL
    RAND_poll();

    // Generate PKCE
    char *code_verifier = generate_random_string(32);
    char *code_challenge = generate_code_challenge(code_verifier);
    char *auth_url = generate_authorize_url(code_challenge);

    printf("Server starting on port: %d\n", PORT);
    printf("Please visit the following URL for authorization:\n");
    printf("%s\n", auth_url);
    printf("Waiting for authorization...\n");

    // Start HTTP server
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
        &request_handler, NULL,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server\n");
        return 1;
    }

    // Set signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Open browser (Linux/Mac)
    char command[1024];
    snprintf(command, sizeof(command), "xdg-open \"%s\" 2>/dev/null || open \"%s\" 2>/dev/null", auth_url, auth_url);
    system(command);

    // Wait for server to stop
    while (server_running) {
        sleep(1);
    }

    printf("Exiting program\n");

    // Cleanup
    MHD_stop_daemon(daemon);
    curl_global_cleanup();
    pthread_mutex_destroy(&auth_state.mutex);

    if (auth_state.auth_data) json_decref(auth_state.auth_data);
    if (auth_state.data_endpoint) free(auth_state.data_endpoint);
    free(code_verifier);
    free(code_challenge);
    free(auth_url);

    return 0;
}