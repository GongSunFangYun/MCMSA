package cn.gsfy;

import com.google.gson.*;
import com.sun.net.httpserver.HttpServer;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class Auth4J {

    // Configuration
    private static final String CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
    private static final String REDIRECT_URI = "http://localhost:3000/proxy/";
    private static final String SCOPE = "XboxLive.signin offline_access";

    // OAuth endpoints
    private static final String AUTHORIZE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
    private static final String TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
    private static final String XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
    private static final String XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
    private static final String MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
    private static final String MC_ENTITLEMENTS_URL = "https://api.minecraftservices.com/entitlements/mcstore";
    private static final String PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

    // PKCE
    private static final String CODE_VERIFIER = generateRandomString();
    private static final String CODE_CHALLENGE = generateCodeChallenge();

    private static final int PORT = 3000;
    private static final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    // Store authentication data
    private static final Map<String, AuthData> authDataMap = new ConcurrentHashMap<>();

    static class AuthData {
        Tokens tokens;
        JsonObject profile;
        PKCE pkce;

        static class Tokens {
            String microsoft_access_token;
            String microsoft_refresh_token;
            String xbl_token;
            String xsts_token;
            String minecraft_access_token;
            int expires_in;
        }

        static class PKCE {
            String code_verifier;
            String code_challenge;
        }
    }

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        // Handle OAuth callback
        server.createContext("/proxy/", exchange -> {
            try {
                URI requestUri = exchange.getRequestURI();
                String query = requestUri.getQuery();
                Map<String, String> queryParams = parseQuery(query);
                String authCode = queryParams.get("code");

                if (authCode != null && !authCode.isEmpty()) {
                    new Thread(() -> {
                        try {
                            handleAuthentication(authCode);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }).start();

                    String response = "Authentication in progress... Please check console for results.";
                    exchange.sendResponseHeaders(200, response.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                } else {
                    String response = "Authorization code not received";
                    exchange.sendResponseHeaders(400, response.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
                String response = "Internal server error: " + e.getMessage();
                exchange.sendResponseHeaders(500, response.getBytes().length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            }
        });

        // Handle data endpoint
        server.createContext("/data/", exchange -> {
            try {
                String path = exchange.getRequestURI().getPath();
                String playerUUID = path.substring("/data/".length()).replace(".json", "");

                AuthData authData = authDataMap.get(playerUUID);
                if (authData != null) {
                    String jsonResponse = gson.toJson(authData);
                    exchange.getResponseHeaders().set("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, jsonResponse.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(jsonResponse.getBytes());
                    }
                } else {
                    String response = "Data not found or expired";
                    exchange.sendResponseHeaders(404, response.getBytes().length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(response.getBytes());
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        server.setExecutor(Executors.newCachedThreadPool());
        server.start();

        System.out.println("Server started on port: " + PORT);
        System.out.println("Please visit the following URL for authorization:");
        System.out.println(generateAuthorizeUrl());
        System.out.println("Waiting for authorization...");

        // Wait for key press to exit
        System.out.println("\nPress Enter to exit at any time...");
        Scanner scanner = new Scanner(System.in);
        scanner.nextLine();
        scanner.close();

        server.stop(0);
        System.out.println("Server stopped.");
    }

    private static void handleAuthentication(String authCode) throws Exception {
        System.out.println("[1/6] Exchanging authorization code for Microsoft token...");
        JsonObject tokenData = exchangeCodeForToken(authCode);
        String accessToken = tokenData.get("access_token").getAsString();

        System.out.println("[2/6] Xbox Live authentication...");
        JsonObject xblData = authenticateXboxLive(accessToken);
        String xblToken = xblData.get("Token").getAsString();
        String userHash = xblData.getAsJsonObject("DisplayClaims")
                .getAsJsonArray("xui")
                .get(0).getAsJsonObject()
                .get("uhs").getAsString();

        System.out.println("[3/6] XSTS authentication...");
        JsonObject xstsData = authenticateXSTS(xblToken);
        String xstsToken = xstsData.get("Token").getAsString();

        System.out.println("[4/6] Getting Minecraft access token...");
        JsonObject mcTokenData = loginWithXbox(userHash, xstsToken);
        String mcAccessToken = mcTokenData.get("access_token").getAsString();

        System.out.println("[5/6] Checking game ownership...");
        JsonObject entitlements = checkGameOwnership(mcAccessToken);
        if (!entitlements.has("items") || entitlements.getAsJsonArray("items").isEmpty()) {
            throw new RuntimeException("This account does not own Minecraft");
        }

        System.out.println("[6/6] Getting Minecraft profile...");
        JsonObject profile = getMinecraftProfile(mcAccessToken);
        String playerUUID = profile.get("id").getAsString();

        // Store data
        AuthData authData = new AuthData();
        authData.tokens = new AuthData.Tokens();
        authData.tokens.microsoft_access_token = accessToken;
        authData.tokens.microsoft_refresh_token = tokenData.get("refresh_token").getAsString();
        authData.tokens.xbl_token = xblToken;
        authData.tokens.xsts_token = xstsToken;
        authData.tokens.minecraft_access_token = mcAccessToken;
        authData.tokens.expires_in = mcTokenData.get("expires_in").getAsInt();

        authData.profile = profile;

        authData.pkce = new AuthData.PKCE();
        authData.pkce.code_verifier = CODE_VERIFIER;
        authData.pkce.code_challenge = CODE_CHALLENGE;

        authDataMap.put(playerUUID, authData);

        System.out.println("\nDone.");
        System.out.println("\nData access URL:");
        System.out.println("http://localhost:" + PORT + "/data/" + playerUUID + ".json");
    }

    private static String generateRandomString() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[(int) Math.ceil(32 / 2.0)];
        random.nextBytes(bytes);
        return bytesToHex(bytes).substring(0, 32);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static String generateCodeChallenge() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(Auth4J.CODE_VERIFIER.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String generateAuthorizeUrl() {
        Map<String, String> params = new HashMap<>();
        params.put("client_id", CLIENT_ID);
        params.put("response_type", "code");
        params.put("redirect_uri", REDIRECT_URI);
        params.put("scope", SCOPE);
        params.put("code_challenge", CODE_CHALLENGE);
        params.put("code_challenge_method", "S256");
        params.put("prompt", "select_account");

        StringBuilder url = new StringBuilder(AUTHORIZE_URL);
        url.append("?");
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) url.append("&");
            url.append(entry.getKey()).append("=").append(entry.getValue());
            first = false;
        }

        return url.toString();
    }

    private static JsonObject exchangeCodeForToken(String authCode) throws Exception {
        Map<String, String> params = new HashMap<>();
        params.put("client_id", CLIENT_ID);
        params.put("code", authCode);
        params.put("redirect_uri", REDIRECT_URI);
        params.put("grant_type", "authorization_code");
        params.put("code_verifier", CODE_VERIFIER);

        String body = buildFormData(params);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return JsonParser.parseString(response.body()).getAsJsonObject();
        } else {
            throw new RuntimeException("Token exchange failed: " + response.body());
        }
    }

    private static JsonObject authenticateXboxLive(String accessToken) throws Exception {
        String[] rpsTickets = {"d=" + accessToken, accessToken};

        for (String rpsTicket : rpsTickets) {
            JsonObject data = new JsonObject();
            JsonObject properties = new JsonObject();
            properties.addProperty("AuthMethod", "RPS");
            properties.addProperty("SiteName", "user.auth.xboxlive.com");
            properties.addProperty("RpsTicket", rpsTicket);
            data.add("Properties", properties);
            data.addProperty("RelyingParty", "http://auth.xboxlive.com");
            data.addProperty("TokenType", "JWT");

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(XBL_AUTH_URL))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(data)))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                return JsonParser.parseString(response.body()).getAsJsonObject();
            }
        }

        throw new RuntimeException("Xbox Live authentication failed");
    }

    private static JsonObject authenticateXSTS(String xblToken) throws Exception {
        JsonObject data = new JsonObject();
        JsonObject properties = new JsonObject();
        properties.addProperty("SandboxId", "RETAIL");

        JsonArray userTokens = new JsonArray();
        userTokens.add(xblToken);
        properties.add("UserTokens", userTokens);

        data.add("Properties", properties);
        data.addProperty("RelyingParty", "rp://api.minecraftservices.com/");
        data.addProperty("TokenType", "JWT");

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(XSTS_AUTH_URL))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(data)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return JsonParser.parseString(response.body()).getAsJsonObject();
        } else {
            throw new RuntimeException("XSTS authentication failed: " + response.body());
        }
    }

    private static JsonObject loginWithXbox(String userHash, String xstsToken) throws Exception {
        JsonObject data = new JsonObject();
        data.addProperty("identityToken", "XBL3.0 x=" + userHash + ";" + xstsToken);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(MC_LOGIN_URL))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(data)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return JsonParser.parseString(response.body()).getAsJsonObject();
        } else {
            throw new RuntimeException("Minecraft login failed: " + response.body());
        }
    }

    private static JsonObject checkGameOwnership(String mcAccessToken) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(MC_ENTITLEMENTS_URL))
                .header("Authorization", "Bearer " + mcAccessToken)
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return JsonParser.parseString(response.body()).getAsJsonObject();
        } else {
            throw new RuntimeException("Game ownership check failed: " + response.body());
        }
    }

    private static JsonObject getMinecraftProfile(String mcAccessToken) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(PROFILE_URL))
                .header("Authorization", "Bearer " + mcAccessToken)
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 200) {
            return JsonParser.parseString(response.body()).getAsJsonObject();
        } else {
            throw new RuntimeException("Profile fetch failed: " + response.body());
        }
    }

    private static String buildFormData(Map<String, String> params) {
        StringBuilder result = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) result.append("&");
            result.append(entry.getKey()).append("=").append(entry.getValue());
            first = false;
        }
        return result.toString();
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null || query.isEmpty()) {
            return result;
        }

        for (String param : query.split("&")) {
            String[] pair = param.split("=");
            if (pair.length == 2) {
                result.put(pair[0], pair[1]);
            }
        }
        return result;
    }
}