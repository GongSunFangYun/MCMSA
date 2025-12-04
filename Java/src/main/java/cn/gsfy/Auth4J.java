package cn.gsfy;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import okhttp3.*;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class Auth4J {

    private static final String CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
    private static final String SCOPE = "XboxLive.signin offline_access openid profile email";

    private static final String DEVICE_CODE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
    private static final String TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
    private static final String XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
    private static final String XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
    private static final String MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
    private static final String PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

    public static class DeviceCodeResponse {
        @SerializedName("device_code")
        public String deviceCode;
        @SerializedName("user_code")
        public String userCode;
        @SerializedName("verification_uri")
        public String verificationUri;
        @SerializedName("expires_in")
        public int expiresIn;
        @SerializedName("interval")
        public int interval;
        @SerializedName("message")
        public String message;
    }

    public static class TokenResponse {
        @SerializedName("access_token")
        public String accessToken;
        @SerializedName("refresh_token")
        public String refreshToken;
        @SerializedName("expires_in")
        public int expiresIn;
        @SerializedName("scope")
        public String scope;
        @SerializedName("token_type")
        public String tokenType;
    }

    @SuppressWarnings("unused")
    public static class XboxAuthRequest {
        public Properties Properties;
        public String RelyingParty = "http://auth.xboxlive.com";
        public String TokenType = "JWT";

        public static class Properties {
            public String AuthMethod = "RPS";
            public String SiteName = "user.auth.xboxlive.com";
            public String RpsTicket;
        }
    }

    public static class XboxAuthResponse {
        @SerializedName("Token")
        public String token;
        @SerializedName("DisplayClaims")
        public DisplayClaims displayClaims;

        public static class DisplayClaims {
            @SerializedName("xui")
            public List<Xui> xui;

            public static class Xui {
                @SerializedName("uhs")
                public String uhs;
            }
        }
    }

    @SuppressWarnings("unused")
    public static class XstsAuthRequest {
        public Properties Properties;
        public String RelyingParty = "rp://api.minecraftservices.com/";
        public String TokenType = "JWT";

        public static class Properties {
            public String SandboxId = "RETAIL";
            @SerializedName("UserTokens")
            public List<String> userTokens;
        }
    }

    public static class XstsAuthResponse {
        @SerializedName("Token")
        public String token;
    }

    public static class MinecraftLoginRequest {
        @SerializedName("identityToken")
        public String identityToken;
    }

    public static class MinecraftLoginResponse {
        @SerializedName("access_token")
        public String accessToken;
        @SerializedName("expires_in")
        public int expiresIn;
    }

    @SuppressWarnings("unused")
    public static class Skin {
        public String id;
        public String state;
        public String url;
        @SerializedName("textureKey")
        public String textureKey;
        public String variant;
    }

    @SuppressWarnings("unused")
    public static class Cape {
        public String id;
        public String state;
        public String url;
        public String alias;
    }

    @SuppressWarnings("unused")
    public static class MinecraftProfile {
        public String id;
        public String name;
        public List<Skin> skins;
        public List<Cape> capes;
        @SerializedName("profileActions")
        public Map<String, String> profileActions;
    }

    public static class AuthResult {
        public Tokens tokens;
        public MinecraftProfile profile;

        public static class Tokens {
            @SerializedName("microsoft_access_token")
            public String microsoftAccessToken;
            @SerializedName("microsoft_refresh_token")
            public String microsoftRefreshToken;
            @SerializedName("xbl_token")
            public String xblToken;
            @SerializedName("xsts_token")
            public String xstsToken;
            @SerializedName("minecraft_access_token")
            public String minecraftAccessToken;
            @SerializedName("expires_in")
            public int expiresIn;
        }
    }

    public static class MinecraftAuthenticator {
        private final OkHttpClient client;
        private final Gson gson;
        private final MediaType jsonMediaType;

        public MinecraftAuthenticator() {
            this.client = new OkHttpClient.Builder()
                    .callTimeout(30, TimeUnit.SECONDS)
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .readTimeout(30, TimeUnit.SECONDS)
                    .build();
            this.gson = new Gson();
            this.jsonMediaType = MediaType.parse("application/json; charset=utf-8");
        }

        public AuthResult authenticate() throws IOException, InterruptedException {
            System.out.println("Minecraft Authentication - Device Code Flow\n");

            try {
                System.out.println("[1/6] Requesting device code...");
                DeviceCodeResponse deviceCodeResponse = requestDeviceCode();

                System.out.println("\nVisit this URL: " + deviceCodeResponse.verificationUri);
                System.out.println("Enter this code: " + deviceCodeResponse.userCode);
                System.out.println("Waiting for authentication...");

                TokenResponse tokenResponse = pollForToken(deviceCodeResponse.deviceCode, deviceCodeResponse.interval);
                System.out.println("\n[2/6] Polling for token...");

                XboxAuthResponse xblData = authenticateWithXboxLive(tokenResponse.accessToken);
                String xblToken = xblData.token;
                String userHash = xblData.displayClaims.xui.getFirst().uhs;
                System.out.println("[3/6] Xbox Live authentication...");

                XstsAuthResponse xstsData = authenticateWithXSTS(xblToken);
                String xstsToken = xstsData.token;
                System.out.println("[4/6] XSTS authentication...");

                MinecraftLoginResponse mcTokenData = loginToMinecraft(userHash, xstsToken);
                String mcAccessToken = mcTokenData.accessToken;
                System.out.println("[5/6] Minecraft login...");

                MinecraftProfile profile = getMinecraftProfile(mcAccessToken);
                System.out.println("[6/6] Getting profile...");

                AuthResult result = new AuthResult();
                result.tokens = new AuthResult.Tokens();
                result.tokens.microsoftAccessToken = tokenResponse.accessToken;
                result.tokens.microsoftRefreshToken = tokenResponse.refreshToken;
                result.tokens.xblToken = xblToken;
                result.tokens.xstsToken = xstsToken;
                result.tokens.minecraftAccessToken = mcAccessToken;
                result.tokens.expiresIn = mcTokenData.expiresIn;
                result.profile = profile;

                return result;

            } catch (Exception e) {
                System.out.println("Authentication failed: " + e.getMessage());
                throw e;
            }
        }

        private DeviceCodeResponse requestDeviceCode() throws IOException {
            FormBody formBody = new FormBody.Builder()
                    .add("client_id", CLIENT_ID)
                    .add("scope", SCOPE)
                    .build();

            Request request = new Request.Builder()
                    .url(DEVICE_CODE_URL)
                    .post(formBody)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .build();

            return executeRequest(request, DeviceCodeResponse.class);
        }

        private TokenResponse pollForToken(String deviceCode, int interval) throws IOException, InterruptedException {
            long pollInterval = Math.max(interval, 5) * 1000L;
            int maxAttempts = 180;

            for (int attempt = 0; attempt < maxAttempts; attempt++) {
                try {
                    FormBody formBody = new FormBody.Builder()
                            .add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                            .add("client_id", CLIENT_ID)
                            .add("device_code", deviceCode)
                            .build();

                    Request request = new Request.Builder()
                            .url(TOKEN_URL)
                            .post(formBody)
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .build();

                    Response response = client.newCall(request).execute();

                    if (response.isSuccessful()) {
                        String body = response.body() != null ? response.body().string() : "";
                        return gson.fromJson(body, TokenResponse.class);
                    } else {
                        String errorBody = response.body() != null ? response.body().string() : "{}";
                        Map<?, ?> errorObj = gson.fromJson(errorBody, Map.class);

                        if ("authorization_pending".equals(errorObj.get("error"))) {
                            Thread.sleep(pollInterval);
                        } else {
                            throw new IOException("Token polling error: " + errorBody);
                        }
                    }
                } catch (Exception e) {
                    if (attempt == maxAttempts - 1) {
                        throw new IOException("Authentication timeout - please try again", e);
                    }
                    Thread.sleep(pollInterval);
                }
            }

            throw new IOException("Authentication timeout - please try again");
        }

        private XboxAuthResponse authenticateWithXboxLive(String accessToken) throws IOException {
            String[] attempts = {"d=" + accessToken, accessToken};

            for (String rpsTicket : attempts) {
                try {
                    XboxAuthRequest requestBody = new XboxAuthRequest();
                    requestBody.Properties = new XboxAuthRequest.Properties();
                    requestBody.Properties.RpsTicket = rpsTicket;

                    String jsonBody = gson.toJson(requestBody);
                    RequestBody body = RequestBody.create(jsonBody, jsonMediaType);

                    Request request = new Request.Builder()
                            .url(XBL_AUTH_URL)
                            .post(body)
                            .header("Content-Type", "application/json")
                            .header("Accept", "application/json")
                            .build();

                    return executeRequest(request, XboxAuthResponse.class);
                } catch (Exception e) {
					continue;
                }
            }

            throw new IOException("Xbox Live authentication failed with both RPS ticket formats");
        }
        private XstsAuthResponse authenticateWithXSTS(String xblToken) throws IOException {
            XstsAuthRequest requestBody = new XstsAuthRequest();
            requestBody.Properties = new XstsAuthRequest.Properties();
            requestBody.Properties.userTokens = Collections.singletonList(xblToken);

            String jsonBody = gson.toJson(requestBody);
            RequestBody body = RequestBody.create(jsonBody, jsonMediaType);

            Request request = new Request.Builder()
                    .url(XSTS_AUTH_URL)
                    .post(body)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build();

            return executeRequest(request, XstsAuthResponse.class);
        }

        private MinecraftLoginResponse loginToMinecraft(String userHash, String xstsToken) throws IOException {
            MinecraftLoginRequest requestBody = new MinecraftLoginRequest();
            requestBody.identityToken = "XBL3.0 x=" + userHash + ";" + xstsToken;

            String jsonBody = gson.toJson(requestBody);
            RequestBody body = RequestBody.create(jsonBody, jsonMediaType);

            Request request = new Request.Builder()
                    .url(MC_LOGIN_URL)
                    .post(body)
                    .header("Content-Type", "application/json")
                    .build();

            return executeRequest(request, MinecraftLoginResponse.class);
        }

        private MinecraftProfile getMinecraftProfile(String mcAccessToken) throws IOException {
            Request request = new Request.Builder()
                    .url(PROFILE_URL)
                    .get()
                    .header("Authorization", "Bearer " + mcAccessToken)
                    .build();

            return executeRequest(request, MinecraftProfile.class);
        }

        private <T> T executeRequest(Request request, Class<T> clazz) throws IOException {
            Response response = client.newCall(request).execute();

            if (!response.isSuccessful()) {
                String errorBody = response.body() != null ? response.body().string() : "";
                throw new IOException("HTTP " + response.code() + ": " + response.message() + ". Body: " + errorBody);
            }

            String body = response.body() != null ? response.body().string() : "";

            if (body.isEmpty() && !clazz.equals(Void.class)) {
                throw new IOException("Empty response body");
            }

            return gson.fromJson(body, clazz);
        }
    }

    public static void main(String[] args) {
        try {
            MinecraftAuthenticator authenticator = new MinecraftAuthenticator();
            AuthResult result = authenticator.authenticate();

            Gson gsonPretty = new GsonBuilder()
                    .setPrettyPrinting()
                    .create();

            System.out.println("\nDone!");
            System.out.println("You can use the following sample code to retrieve any field from the returned JSON:\n");
            System.out.println("MinecraftAuthenticator authenticator = new MinecraftAuthenticator();");
            System.out.println("AuthResult authResult = authenticator.authenticate();");
            System.out.println("String accessToken = authResult.tokens.minecraftAccessToken;");
            System.out.println("System.out.println(accessToken);\n");
            System.out.println("Below is the JSON returned from your recent login operation:\n");

            System.out.println(gsonPretty.toJson(result));
        } catch (Exception e) {
            System.err.println("Authentication failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}