#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <time.h>
#include <unistd.h>

#define CLIENT_ID "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
#define SCOPE "XboxLive.signin offline_access openid profile email"

#define DEVICE_CODE_URL "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
#define TOKEN_URL "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
#define XBL_AUTH_URL "https://user.auth.xboxlive.com/user/authenticate"
#define XSTS_AUTH_URL "https://xsts.auth.xboxlive.com/xsts/authorize"
#define MC_LOGIN_URL "https://api.minecraftservices.com/authentication/login_with_xbox"
#define PROFILE_URL "https://api.minecraftservices.com/minecraft/profile"

typedef struct {
    char *device_code;
    char *user_code;
    char *verification_uri;
    int expires_in;
    int interval;
    char *message;
} DeviceCodeResponse;

typedef struct {
    char *access_token;
    char *refresh_token;
    int expires_in;
    char *scope;
    char *token_type;
} TokenResponse;

typedef struct {
    char *token;
    char *uhs;
} XboxAuthResponse;

typedef struct {
    char *token;
} XstsAuthResponse;

typedef struct {
    char *access_token;
    int expires_in;
} MinecraftLoginResponse;

typedef struct {
    char *id;
    char *name;
} MinecraftProfile;

typedef struct {
    struct {
        char *microsoft_access_token;
        char *microsoft_refresh_token;
        char *xbl_token;
        char *xsts_token;
        char *minecraft_access_token;
        int expires_in;
    } tokens;
    MinecraftProfile profile;
} AuthResult;

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(ptr == NULL) {
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static char* http_post_form(const char *url, const char *post_fields) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            chunk.memory = NULL;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return chunk.memory;
}

static char* http_post_json(const char *url, const char *json_data) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            chunk.memory = NULL;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return chunk.memory;
}

static char* http_get_json(const char *url, const char *auth_header) {
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1);
    chunk.size = 0;

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        if(auth_header) {
            headers = curl_slist_append(headers, auth_header);
        }
        headers = curl_slist_append(headers, "Accept: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            free(chunk.memory);
            chunk.memory = NULL;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    return chunk.memory;
}

static DeviceCodeResponse* request_device_code() {
    char post_fields[512];
    snprintf(post_fields, sizeof(post_fields),
             "client_id=%s&scope=%s", CLIENT_ID, SCOPE);

    char *response = http_post_form(DEVICE_CODE_URL, post_fields);
    if(!response) return NULL;

    json_t *root;
    json_error_t error;

    root = json_loads(response, 0, &error);
    free(response);

    if(!root) {
        fprintf(stderr, "JSON parse error: %s\n", error.text);
        return NULL;
    }

    DeviceCodeResponse *result = malloc(sizeof(DeviceCodeResponse));
    memset(result, 0, sizeof(DeviceCodeResponse));

    json_t *device_code = json_object_get(root, "device_code");
    json_t *user_code = json_object_get(root, "user_code");
    json_t *verification_uri = json_object_get(root, "verification_uri");
    json_t *expires_in = json_object_get(root, "expires_in");
    json_t *interval = json_object_get(root, "interval");
    json_t *message = json_object_get(root, "message");

    if(json_is_string(device_code))
        result->device_code = strdup(json_string_value(device_code));
    if(json_is_string(user_code))
        result->user_code = strdup(json_string_value(user_code));
    if(json_is_string(verification_uri))
        result->verification_uri = strdup(json_string_value(verification_uri));
    if(json_is_integer(expires_in))
        result->expires_in = json_integer_value(expires_in);
    if(json_is_integer(interval))
        result->interval = json_integer_value(interval);
    if(json_is_string(message))
        result->message = strdup(json_string_value(message));

    json_decref(root);
    return result;
}

static TokenResponse* poll_for_token(const char *device_code, int interval) {
    int poll_interval = interval > 5 ? interval : 5;
    int max_attempts = 180;

    for(int attempt = 0; attempt < max_attempts; attempt++) {
        char post_fields[1024];
        snprintf(post_fields, sizeof(post_fields),
                 "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&device_code=%s",
                 CLIENT_ID, device_code);

        char *response = http_post_form(TOKEN_URL, post_fields);
        if(!response) {
            sleep(poll_interval);
            continue;
        }

        json_t *root;
        json_error_t error;
        root = json_loads(response, 0, &error);

        if(root) {
            json_t *error_field = json_object_get(root, "error");
            if(json_is_string(error_field)) {
                const char *error_value = json_string_value(error_field);
                if(strcmp(error_value, "authorization_pending") == 0) {
                    json_decref(root);
                    free(response);
                    sleep(poll_interval);
                    continue;
                }
            }

            json_t *access_token = json_object_get(root, "access_token");
            json_t *refresh_token = json_object_get(root, "refresh_token");
            json_t *expires_in = json_object_get(root, "expires_in");
            json_t *scope = json_object_get(root, "scope");
            json_t *token_type = json_object_get(root, "token_type");

            if(json_is_string(access_token) && json_is_string(refresh_token)) {
                TokenResponse *result = malloc(sizeof(TokenResponse));
                memset(result, 0, sizeof(TokenResponse));

                result->access_token = strdup(json_string_value(access_token));
                result->refresh_token = strdup(json_string_value(refresh_token));

                if(json_is_integer(expires_in))
                    result->expires_in = json_integer_value(expires_in);
                if(json_is_string(scope))
                    result->scope = strdup(json_string_value(scope));
                if(json_is_string(token_type))
                    result->token_type = strdup(json_string_value(token_type));

                json_decref(root);
                free(response);
                return result;
            }

            json_decref(root);
        } else {
            fprintf(stderr, "JSON parse error: %s\n", error.text);
        }

        free(response);

        if(attempt == max_attempts - 1) {
            fprintf(stderr, "Authentication timeout - please try again\n");
            return NULL;
        }

        sleep(poll_interval);
    }

    return NULL;
}

static XboxAuthResponse* authenticate_with_xbox_live(const char *access_token) {
    const char *attempts[] = {
        "d=%s",
        "%s"
    };

    for(int i = 0; i < 2; i++) {
        char rps_ticket[2048];
        snprintf(rps_ticket, sizeof(rps_ticket), attempts[i], access_token);

        char json_request[4096];
        snprintf(json_request, sizeof(json_request),
                 "{\"Properties\":{\"AuthMethod\":\"RPS\",\"SiteName\":\"user.auth.xboxlive.com\",\"RpsTicket\":\"%s\"},\"RelyingParty\":\"http://auth.xboxlive.com\",\"TokenType\":\"JWT\"}",
                 rps_ticket);

        char *response = http_post_json(XBL_AUTH_URL, json_request);
        if(!response) continue;

        json_t *root;
        json_error_t error;
        root = json_loads(response, 0, &error);
        free(response);

        if(root) {
            json_t *token = json_object_get(root, "Token");
            json_t *display_claims = json_object_get(root, "DisplayClaims");

            if(json_is_string(token) && json_is_object(display_claims)) {
                json_t *xui = json_object_get(display_claims, "xui");
                if(json_is_array(xui) && json_array_size(xui) > 0) {
                    json_t *first_xui = json_array_get(xui, 0);
                    json_t *uhs = json_object_get(first_xui, "uhs");

                    if(json_is_string(uhs)) {
                        XboxAuthResponse *result = malloc(sizeof(XboxAuthResponse));
                        memset(result, 0, sizeof(XboxAuthResponse));

                        result->token = strdup(json_string_value(token));
                        result->uhs = strdup(json_string_value(uhs));

                        json_decref(root);
                        return result;
                    }
                }
            }

            json_decref(root);
        }
    }

    fprintf(stderr, "Xbox Live authentication failed with both RPS ticket formats\n");
    return NULL;
}

static XstsAuthResponse* authenticate_with_xsts(const char *xbl_token) {
    char json_request[4096];
    snprintf(json_request, sizeof(json_request),
             "{\"Properties\":{\"SandboxId\":\"RETAIL\",\"UserTokens\":[\"%s\"]},\"RelyingParty\":\"rp://api.minecraftservices.com/\",\"TokenType\":\"JWT\"}",
             xbl_token);

    char *response = http_post_json(XSTS_AUTH_URL, json_request);
    if(!response) return NULL;

    json_t *root;
    json_error_t error;
    root = json_loads(response, 0, &error);
    free(response);

    if(!root) {
        fprintf(stderr, "JSON parse error: %s\n", error.text);
        return NULL;
    }

    json_t *token = json_object_get(root, "Token");

    if(!json_is_string(token)) {
        json_decref(root);
        return NULL;
    }

    XstsAuthResponse *result = malloc(sizeof(XstsAuthResponse));
    memset(result, 0, sizeof(XstsAuthResponse));
    result->token = strdup(json_string_value(token));

    json_decref(root);
    return result;
}

static MinecraftLoginResponse* login_to_minecraft(const char *user_hash, const char *xsts_token) {
    char identity_token[4096];
    snprintf(identity_token, sizeof(identity_token), "XBL3.0 x=%s;%s", user_hash, xsts_token);

    char json_request[8192];
    snprintf(json_request, sizeof(json_request),
             "{\"identityToken\":\"%s\"}", identity_token);

    char *response = http_post_json(MC_LOGIN_URL, json_request);
    if(!response) return NULL;

    json_t *root;
    json_error_t error;
    root = json_loads(response, 0, &error);
    free(response);

    if(!root) {
        fprintf(stderr, "JSON parse error: %s\n", error.text);
        return NULL;
    }

    json_t *access_token = json_object_get(root, "access_token");
    json_t *expires_in = json_object_get(root, "expires_in");

    if(!json_is_string(access_token) || !json_is_integer(expires_in)) {
        json_decref(root);
        return NULL;
    }

    MinecraftLoginResponse *result = malloc(sizeof(MinecraftLoginResponse));
    memset(result, 0, sizeof(MinecraftLoginResponse));

    result->access_token = strdup(json_string_value(access_token));
    result->expires_in = json_integer_value(expires_in);

    json_decref(root);
    return result;
}

static MinecraftProfile* get_minecraft_profile(const char *mc_access_token) {
    char auth_header[8192];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", mc_access_token);

    char *response = http_get_json(PROFILE_URL, auth_header);
    if(!response) return NULL;

    json_t *root;
    json_error_t error;
    root = json_loads(response, 0, &error);
    free(response);

    if(!root) {
        fprintf(stderr, "JSON parse error: %s\n", error.text);
        return NULL;
    }

    json_t *id = json_object_get(root, "id");
    json_t *name = json_object_get(root, "name");

    if(!json_is_string(id) || !json_is_string(name)) {
        json_decref(root);
        return NULL;
    }

    MinecraftProfile *result = malloc(sizeof(MinecraftProfile));
    memset(result, 0, sizeof(MinecraftProfile));

    result->id = strdup(json_string_value(id));
    result->name = strdup(json_string_value(name));

    json_decref(root);
    return result;
}

static void free_device_code_response(DeviceCodeResponse *resp) {
    if(!resp) return;
    free(resp->device_code);
    free(resp->user_code);
    free(resp->verification_uri);
    free(resp->message);
    free(resp);
}

static void free_token_response(TokenResponse *resp) {
    if(!resp) return;
    free(resp->access_token);
    free(resp->refresh_token);
    free(resp->scope);
    free(resp->token_type);
    free(resp);
}

static void free_xbox_auth_response(XboxAuthResponse *resp) {
    if(!resp) return;
    free(resp->token);
    free(resp->uhs);
    free(resp);
}

static void free_xsts_auth_response(XstsAuthResponse *resp) {
    if(!resp) return;
    free(resp->token);
    free(resp);
}

static void free_minecraft_login_response(MinecraftLoginResponse *resp) {
    if(!resp) return;
    free(resp->access_token);
    free(resp);
}

static void free_minecraft_profile(MinecraftProfile *profile) {
    if(!profile) return;
    free(profile->id);
    free(profile->name);
    free(profile);
}

static void free_auth_result(AuthResult *result) {
    if(!result) return;

    free(result->tokens.microsoft_access_token);
    free(result->tokens.microsoft_refresh_token);
    free(result->tokens.xbl_token);
    free(result->tokens.xsts_token);
    free(result->tokens.minecraft_access_token);

    free_minecraft_profile(&result->profile);
}

static AuthResult* authenticate() {
    printf("Minecraft Authentication - Device Code Flow\n\n");

    curl_global_init(CURL_GLOBAL_ALL);

    printf("[1/6] Requesting device code...\n");
    DeviceCodeResponse *device_code_resp = request_device_code();
    if(!device_code_resp) {
        curl_global_cleanup();
        return NULL;
    }

    printf("\nVisit this URL: %s\n", device_code_resp->verification_uri);
    printf("Enter this code: %s\n", device_code_resp->user_code);
    printf("Waiting for authentication...\n");

    TokenResponse *token_resp = poll_for_token(device_code_resp->device_code, device_code_resp->interval);
    free_device_code_response(device_code_resp);

    if(!token_resp) {
        curl_global_cleanup();
        return NULL;
    }

    printf("\n[2/6] Polling for token...\n");

    printf("[3/6] Xbox Live authentication...\n");
    XboxAuthResponse *xbox_resp = authenticate_with_xbox_live(token_resp->access_token);
    if(!xbox_resp) {
        free_token_response(token_resp);
        curl_global_cleanup();
        return NULL;
    }

    printf("[4/6] XSTS authentication...\n");
    XstsAuthResponse *xsts_resp = authenticate_with_xsts(xbox_resp->token);
    if(!xsts_resp) {
        free_xbox_auth_response(xbox_resp);
        free_token_response(token_resp);
        curl_global_cleanup();
        return NULL;
    }

    printf("[5/6] Minecraft login...\n");
    MinecraftLoginResponse *mc_login_resp = login_to_minecraft(xbox_resp->uhs, xsts_resp->token);
    if(!mc_login_resp) {
        free_xsts_auth_response(xsts_resp);
        free_xbox_auth_response(xbox_resp);
        free_token_response(token_resp);
        curl_global_cleanup();
        return NULL;
    }

    printf("[6/6] Getting profile...\n");
    MinecraftProfile *profile = get_minecraft_profile(mc_login_resp->access_token);
    if(!profile) {
        free_minecraft_login_response(mc_login_resp);
        free_xsts_auth_response(xsts_resp);
        free_xbox_auth_response(xbox_resp);
        free_token_response(token_resp);
        curl_global_cleanup();
        return NULL;
    }

    AuthResult *result = malloc(sizeof(AuthResult));
    memset(result, 0, sizeof(AuthResult));

    result->tokens.microsoft_access_token = strdup(token_resp->access_token);
    result->tokens.microsoft_refresh_token = strdup(token_resp->refresh_token);
    result->tokens.xbl_token = strdup(xbox_resp->token);
    result->tokens.xsts_token = strdup(xsts_resp->token);
    result->tokens.minecraft_access_token = strdup(mc_login_resp->access_token);
    result->tokens.expires_in = mc_login_resp->expires_in;

    result->profile.id = strdup(profile->id);
    result->profile.name = strdup(profile->name);

    free_minecraft_profile(profile);
    free_minecraft_login_response(mc_login_resp);
    free_xsts_auth_response(xsts_resp);
    free_xbox_auth_response(xbox_resp);
    free_token_response(token_resp);

    curl_global_cleanup();

    return result;
}

static void print_json(const AuthResult *result) {
    if(!result) return;

    printf("{\n");
    printf("  \"tokens\": {\n");
    printf("    \"microsoft_access_token\": \"%s\",\n", result->tokens.microsoft_access_token);
    printf("    \"microsoft_refresh_token\": \"%s\",\n", result->tokens.microsoft_refresh_token);
    printf("    \"xbl_token\": \"%s\",\n", result->tokens.xbl_token);
    printf("    \"xsts_token\": \"%s\",\n", result->tokens.xsts_token);
    printf("    \"minecraft_access_token\": \"%s\",\n", result->tokens.minecraft_access_token);
    printf("    \"expires_in\": %d\n", result->tokens.expires_in);
    printf("  },\n");
    printf("  \"profile\": {\n");
    printf("    \"id\": \"%s\",\n", result->profile.id);
    printf("    \"name\": \"%s\"\n", result->profile.name);
    printf("  }\n");
    printf("}\n");
}

int main() {
    AuthResult *result = authenticate();

    if(result) {
        printf("\nDone!\n");
        printf("You can use the following sample code to retrieve any field from the returned JSON:\n\n");
        printf("AuthResult *result = authenticate();\n");
        printf("char *access_token = result->tokens.minecraft_access_token;\n");
        printf("printf(\"%%s\\n\", access_token);\n\n");
        printf("Below is the JSON returned from your recent login operation:\n\n");

        print_json(result);
        free_auth_result(result);
        free(result);
    } else {
        printf("Authentication failed!\n");
    }

    return 0;
}