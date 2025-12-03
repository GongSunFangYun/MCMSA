#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

// 配置
#define CLIENT_ID "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
#define SCOPE "XboxLive.signin%20offline_access%20openid%20profile%20email"

// API端点
#define DEVICE_CODE_URL "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
#define TOKEN_URL "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
#define XBL_AUTH_URL "https://user.auth.xboxlive.com/user/authenticate"
#define XSTS_AUTH_URL "https://xsts.auth.xboxlive.com/xsts/authorize"
#define MC_LOGIN_URL "https://api.minecraftservices.com/authentication/login_with_xbox"
#define PROFILE_URL "https://api.minecraftservices.com/minecraft/profile"

// 回调数据结构
struct MemoryStruct {
    char *memory;
    size_t size;
};

// 初始化内存结构
static void init_memory(struct MemoryStruct *chunk) {
    chunk->memory = malloc(1);
    chunk->size = 0;
}

// 释放内存结构
static void free_memory(struct MemoryStruct *chunk) {
    if (chunk->memory) free(chunk->memory);
    chunk->memory = NULL;
    chunk->size = 0;
}

// CURL写回调函数
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    
    return realsize;
}

// 执行HTTP POST请求
static int http_post(const char *url, const char *post_data, const char *content_type, 
                     struct MemoryStruct *response) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    
    curl = curl_easy_init();
    if (!curl) return -1;
    
    // 设置请求头
    char content_type_header[256];
    snprintf(content_type_header, sizeof(content_type_header), "Content-Type: %s", content_type);
    headers = curl_slist_append(headers, content_type_header);
    
    // 设置CURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Minecraft-Auth/1.0");
    
    res = curl_easy_perform(curl);
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK && http_code == 200) ? 0 : -1;
}

// 执行HTTP GET请求
static int http_get(const char *url, const char *auth_header, struct MemoryStruct *response) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    
    curl = curl_easy_init();
    if (!curl) return -1;
    
    // 设置请求头
    if (auth_header) {
        headers = curl_slist_append(headers, auth_header);
    }
    
    // 设置CURL选项
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Minecraft-Auth/1.0");
    
    res = curl_easy_perform(curl);
    
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    
    return (res == CURLE_OK && http_code == 200) ? 0 : -1;
}

// 获取设备代码
static int get_device_code(struct MemoryStruct *response) {
    char post_data[512];
    snprintf(post_data, sizeof(post_data), 
             "client_id=%s&scope=%s", CLIENT_ID, SCOPE);
    
    printf("[1/7] Requesting device code...\n");
    return http_post(DEVICE_CODE_URL, post_data, "application/x-www-form-urlencoded", response);
}

// 轮询获取访问令牌
static int poll_for_token(const char *device_code, int interval, struct MemoryStruct *response) {
    char post_data[512];
    snprintf(post_data, sizeof(post_data), 
             "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=%s&device_code=%s",
             CLIENT_ID, device_code);
    
    int max_attempts = 180;
    printf("[2/7] Polling for token");
    fflush(stdout);
    
    for (int i = 0; i < max_attempts; i++) {
        if (http_post(TOKEN_URL, post_data, "application/x-www-form-urlencoded", response) == 0) {
            cJSON *root = cJSON_Parse(response->memory);
            if (root) {
                cJSON *access_token = cJSON_GetObjectItem(root, "access_token");
                if (cJSON_IsString(access_token) && access_token->valuestring != NULL) {
                    cJSON_Delete(root);
                    printf(" Done\n");
                    return 0;
                }
                cJSON_Delete(root);
            }
        } else {
            cJSON *error_json = cJSON_Parse(response->memory);
            if (error_json) {
                cJSON *error = cJSON_GetObjectItem(error_json, "error");
                if (error && strcmp(error->valuestring, "authorization_pending") == 0) {
                    printf(".");
                    fflush(stdout);
                    free_memory(response);
                    init_memory(response);
                    sleep(interval > 0 ? interval : 5);
                    cJSON_Delete(error_json);
                    continue;
                }
                cJSON_Delete(error_json);
            }
        }
        printf("\n");
        return -1;
    }
    
    printf("\nTimeout\n");
    return -1;
}

// Xbox Live认证
static int authenticate_xbox_live(const char *access_token, struct MemoryStruct *response) {
    printf("[4/7] Xbox Live authentication...\n");
    
    // 尝试两种格式的RPS票据
    const char *rps_tickets[] = {
        "d=%s",
        "%s"
    };
    
    for (int i = 0; i < 2; i++) {
        char rps_ticket[2048];
        snprintf(rps_ticket, sizeof(rps_ticket), rps_tickets[i], access_token);
        
        char json_payload[4096];
        snprintf(json_payload, sizeof(json_payload),
                 "{\"Properties\":{\"AuthMethod\":\"RPS\",\"SiteName\":\"user.auth.xboxlive.com\",\"RpsTicket\":\"%s\"},\"RelyingParty\":\"http://auth.xboxlive.com\",\"TokenType\":\"JWT\"}",
                 rps_ticket);
        
        if (http_post(XBL_AUTH_URL, json_payload, "application/json", response) == 0) {
            cJSON *root = cJSON_Parse(response->memory);
            if (root) {
                cJSON *token = cJSON_GetObjectItem(root, "Token");
                if (cJSON_IsString(token) && token->valuestring != NULL) {
                    cJSON_Delete(root);
                    return 0;
                }
                cJSON_Delete(root);
            }
        }
        free_memory(response);
        init_memory(response);
    }
    
    return -1;
}

// XSTS认证
static int authenticate_xsts(const char *xbl_token, struct MemoryStruct *response) {
    printf("[5/7] XSTS authentication...\n");
    
    char json_payload[4096];
    snprintf(json_payload, sizeof(json_payload),
             "{\"Properties\":{\"SandboxId\":\"RETAIL\",\"UserTokens\":[\"%s\"]},\"RelyingParty\":\"rp://api.minecraftservices.com/\",\"TokenType\":\"JWT\"}",
             xbl_token);
    
    return http_post(XSTS_AUTH_URL, json_payload, "application/json", response);
}

// Minecraft登录
static int login_to_minecraft(const char *user_hash, const char *xsts_token, struct MemoryStruct *response) {
    printf("[6/7] Minecraft login...\n");
    
    char json_payload[4096];
    snprintf(json_payload, sizeof(json_payload),
             "{\"identityToken\":\"XBL3.0 x=%s;%s\"}",
             user_hash, xsts_token);
    
    return http_post(MC_LOGIN_URL, json_payload, "application/json", response);
}

// 获取Minecraft档案
static int get_minecraft_profile(const char *mc_access_token, struct MemoryStruct *response) {
    printf("[7/7] Getting profile...\n");
    
    char auth_header[1024];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", mc_access_token);
    
    return http_get(PROFILE_URL, auth_header, response);
}

// 主要认证流程
int main(void) {
    curl_global_init(CURL_GLOBAL_ALL);
    
    struct MemoryStruct device_code_resp, token_resp, xbl_resp, xsts_resp, mc_resp, profile_resp;
    init_memory(&device_code_resp);
    init_memory(&token_resp);
    init_memory(&xbl_resp);
    init_memory(&xsts_resp);
    init_memory(&mc_resp);
    init_memory(&profile_resp);
    
    printf("Minecraft Authentication - Device Code Flow\n\n");
    
    // 1. 获取设备代码
    if (get_device_code(&device_code_resp) != 0) {
        fprintf(stderr, "Failed to get device code\n");
        goto cleanup;
    }
    
    cJSON *device_code_json = cJSON_Parse(device_code_resp.memory);
    if (!device_code_json) {
        fprintf(stderr, "Failed to parse device code response\n");
        goto cleanup;
    }
    
    cJSON *verification_uri = cJSON_GetObjectItem(device_code_json, "verification_uri");
    cJSON *user_code = cJSON_GetObjectItem(device_code_json, "user_code");
    cJSON *device_code = cJSON_GetObjectItem(device_code_json, "device_code");
    cJSON *interval = cJSON_GetObjectItem(device_code_json, "interval");
    
    if (!verification_uri || !user_code || !device_code) {
        fprintf(stderr, "Invalid device code response\n");
        cJSON_Delete(device_code_json);
        goto cleanup;
    }
    
    printf("\nPlease visit: %s\n", verification_uri->valuestring);
    printf("Enter this code: %s\n", user_code->valuestring);
    printf("\nWaiting for authentication...\n");
    
    // 2. 轮询令牌
    if (poll_for_token(device_code->valuestring, interval ? interval->valueint : 5, &token_resp) != 0) {
        cJSON_Delete(device_code_json);
        fprintf(stderr, "Failed to get access token\n");
        goto cleanup;
    }
    
    cJSON_Delete(device_code_json);
    printf("[3/7] Microsoft token obtained\n");
    
    // 解析令牌响应
    cJSON *token_json = cJSON_Parse(token_resp.memory);
    if (!token_json) {
        fprintf(stderr, "Failed to parse token response\n");
        goto cleanup;
    }
    
    cJSON *ms_access_token = cJSON_GetObjectItem(token_json, "access_token");
    cJSON *refresh_token = cJSON_GetObjectItem(token_json, "refresh_token");
    
    if (!ms_access_token) {
        fprintf(stderr, "No access token in response\n");
        cJSON_Delete(token_json);
        goto cleanup;
    }
    
    // 3. Xbox Live认证
    if (authenticate_xbox_live(ms_access_token->valuestring, &xbl_resp) != 0) {
        fprintf(stderr, "Xbox Live authentication failed\n");
        cJSON_Delete(token_json);
        goto cleanup;
    }
    
    cJSON *xbl_json = cJSON_Parse(xbl_resp.memory);
    if (!xbl_json) {
        fprintf(stderr, "Failed to parse Xbox Live response\n");
        cJSON_Delete(token_json);
        goto cleanup;
    }
    
    cJSON *xbl_token = cJSON_GetObjectItem(xbl_json, "Token");
    cJSON *display_claims = cJSON_GetObjectItem(xbl_json, "DisplayClaims");
    
    if (!xbl_token || !display_claims) {
        fprintf(stderr, "Invalid Xbox Live response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        goto cleanup;
    }
    
    // 获取user hash
    cJSON *xui = cJSON_GetObjectItem(display_claims, "xui");
    if (!xui || !cJSON_IsArray(xui) || cJSON_GetArraySize(xui) == 0) {
        fprintf(stderr, "No user hash in Xbox Live response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        goto cleanup;
    }
    
    cJSON *first_xui = cJSON_GetArrayItem(xui, 0);
    cJSON *user_hash = cJSON_GetObjectItem(first_xui, "uhs");
    
    if (!user_hash) {
        fprintf(stderr, "No user hash in Xbox Live response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        goto cleanup;
    }
    
    // 4. XSTS认证
    if (authenticate_xsts(xbl_token->valuestring, &xsts_resp) != 0) {
        fprintf(stderr, "XSTS authentication failed\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        goto cleanup;
    }
    
    cJSON *xsts_json = cJSON_Parse(xsts_resp.memory);
    if (!xsts_json) {
        fprintf(stderr, "Failed to parse XSTS response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        goto cleanup;
    }
    
    cJSON *xsts_token = cJSON_GetObjectItem(xsts_json, "Token");
    if (!xsts_token) {
        fprintf(stderr, "No XSTS token in response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        cJSON_Delete(xsts_json);
        goto cleanup;
    }
    
    // 5. Minecraft登录
    if (login_to_minecraft(user_hash->valuestring, xsts_token->valuestring, &mc_resp) != 0) {
        fprintf(stderr, "Minecraft login failed\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        cJSON_Delete(xsts_json);
        goto cleanup;
    }
    
    cJSON *mc_json = cJSON_Parse(mc_resp.memory);
    if (!mc_json) {
        fprintf(stderr, "Failed to parse Minecraft response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        cJSON_Delete(xsts_json);
        goto cleanup;
    }
    
    cJSON *mc_access_token = cJSON_GetObjectItem(mc_json, "access_token");
    if (!mc_access_token) {
        fprintf(stderr, "No Minecraft access token in response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        cJSON_Delete(xsts_json);
        cJSON_Delete(mc_json);
        goto cleanup;
    }
    
    // 6. 获取Minecraft档案
    if (get_minecraft_profile(mc_access_token->valuestring, &profile_resp) != 0) {
        fprintf(stderr, "Failed to get Minecraft profile\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        cJSON_Delete(xsts_json);
        cJSON_Delete(mc_json);
        goto cleanup;
    }
    
    cJSON *profile_json = cJSON_Parse(profile_resp.memory);
    if (!profile_json) {
        fprintf(stderr, "Failed to parse profile response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        cJSON_Delete(xsts_json);
        cJSON_Delete(mc_json);
        goto cleanup;
    }
    
    cJSON *player_uuid = cJSON_GetObjectItem(profile_json, "id");
    cJSON *player_name = cJSON_GetObjectItem(profile_json, "name");
    
    if (!player_uuid || !player_name) {
        fprintf(stderr, "Invalid profile response\n");
        cJSON_Delete(token_json);
        cJSON_Delete(xbl_json);
        cJSON_Delete(xsts_json);
        cJSON_Delete(mc_json);
        cJSON_Delete(profile_json);
        goto cleanup;
    }
    
    // 创建完整的认证结果JSON
    cJSON *auth_result = cJSON_CreateObject();
    
    // 添加时间戳
    time_t now = time(NULL);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    cJSON_AddStringToObject(auth_result, "timestamp", timestamp);
    
    // 添加玩家信息
    cJSON *player_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(player_obj, "id", player_uuid->valuestring);
    cJSON_AddStringToObject(player_obj, "name", player_name->valuestring);
    cJSON_AddItemToObject(auth_result, "player", player_obj);
    
    // 添加令牌信息
    cJSON *tokens_obj = cJSON_CreateObject();
    
    cJSON *microsoft_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(microsoft_obj, "access_token", ms_access_token->valuestring);
    if (refresh_token) cJSON_AddStringToObject(microsoft_obj, "refresh_token", refresh_token->valuestring);
    cJSON_AddNumberToObject(microsoft_obj, "expires_in", cJSON_GetObjectItem(token_json, "expires_in")->valueint);
    cJSON_AddStringToObject(microsoft_obj, "scope", cJSON_GetObjectItem(token_json, "scope")->valuestring);
    cJSON_AddItemToObject(tokens_obj, "microsoft", microsoft_obj);
    
    cJSON *xbox_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(xbox_obj, "xbl_token", xbl_token->valuestring);
    cJSON_AddStringToObject(xbox_obj, "xsts_token", xsts_token->valuestring);
    cJSON_AddItemToObject(tokens_obj, "xbox", xbox_obj);
    
    cJSON *minecraft_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(minecraft_obj, "access_token", mc_access_token->valuestring);
    cJSON_AddNumberToObject(minecraft_obj, "expires_in", cJSON_GetObjectItem(mc_json, "expires_in")->valueint);
    cJSON_AddItemToObject(tokens_obj, "minecraft", minecraft_obj);
    
    cJSON_AddItemToObject(auth_result, "tokens", tokens_obj);
    cJSON_AddItemToObject(auth_result, "profile", cJSON_Duplicate(profile_json, 1));
    
    printf("\n--- AUTHENTICATION DATA ---\n");
    char *auth_result_str = cJSON_Print(auth_result);
    printf("%s\n", auth_result_str);
    free(auth_result_str);
    
    // 清理
    cJSON_Delete(auth_result);
    cJSON_Delete(token_json);
    cJSON_Delete(xbl_json);
    cJSON_Delete(xsts_json);
    cJSON_Delete(mc_json);
    cJSON_Delete(profile_json);
    
cleanup:
    free_memory(&device_code_resp);
    free_memory(&token_resp);
    free_memory(&xbl_resp);
    free_memory(&xsts_resp);
    free_memory(&mc_resp);
    free_memory(&profile_resp);
    
    curl_global_cleanup();
    return 0;
}