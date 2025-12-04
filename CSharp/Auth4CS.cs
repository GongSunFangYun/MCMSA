using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Auth4CS
{
    public class DeviceCodeResponse
    {
        [JsonPropertyName("device_code")]
        public string DeviceCode { get; set; }
        
        [JsonPropertyName("user_code")]
        public string UserCode { get; set; }
        
        [JsonPropertyName("verification_uri")]
        public string VerificationUri { get; set; }
        
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
        
        [JsonPropertyName("interval")]
        public int Interval { get; set; }
        
        [JsonPropertyName("message")]
        public string Message { get; set; }
    }

    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }
        
        [JsonPropertyName("refresh_token")]
        public string RefreshToken { get; set; }
        
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
        
        [JsonPropertyName("scope")]
        public string Scope { get; set; }
        
        [JsonPropertyName("token_type")]
        public string TokenType { get; set; }
    }

    public class XboxAuthRequest
    {
        public PropertiesData Properties { get; set; }
        public string RelyingParty { get; set; } = "http://auth.xboxlive.com";
        public string TokenType { get; set; } = "JWT";

        public class PropertiesData
        {
            public string AuthMethod { get; set; } = "RPS";
            public string SiteName { get; set; } = "user.auth.xboxlive.com";
            public string RpsTicket { get; set; }
        }
    }

    public class XboxAuthResponse
    {
        [JsonPropertyName("Token")]
        public string Token { get; set; }
        
        [JsonPropertyName("DisplayClaims")]
        public DisplayClaimsData DisplayClaims { get; set; }

        public class DisplayClaimsData
        {
            [JsonPropertyName("xui")]
            public List<XuiData> Xui { get; set; }

            public class XuiData
            {
                [JsonPropertyName("uhs")]
                public string Uhs { get; set; }
            }
        }
    }

    public class XstsAuthRequest
    {
        public PropertiesData Properties { get; set; }
        public string RelyingParty { get; set; } = "rp://api.minecraftservices.com/";
        public string TokenType { get; set; } = "JWT";

        public class PropertiesData
        {
            public string SandboxId { get; set; } = "RETAIL";
            
            [JsonPropertyName("UserTokens")]
            public List<string> UserTokens { get; set; }
        }
    }

    public class XstsAuthResponse
    {
        [JsonPropertyName("Token")]
        public string Token { get; set; }
    }

    public class MinecraftLoginRequest
    {
        [JsonPropertyName("identityToken")]
        public string IdentityToken { get; set; }
    }

    public class MinecraftLoginResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; }
        
        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }
    }

    public class Skin
    {
        public string Id { get; set; }
        public string State { get; set; }
        public string Url { get; set; }
        
        [JsonPropertyName("textureKey")]
        public string TextureKey { get; set; }
        public string Variant { get; set; }
    }

    public class Cape
    {
        public string Id { get; set; }
        public string State { get; set; }
        public string Url { get; set; }
        public string Alias { get; set; }
    }

    public class MinecraftProfile
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public List<Skin> Skins { get; set; } = new List<Skin>();
        public List<Cape> Capes { get; set; } = new List<Cape>();
        
        [JsonPropertyName("profileActions")]
        public Dictionary<string, string> ProfileActions { get; set; } = new Dictionary<string, string>();
    }

    public class AuthResult
    {
        public TokensData Tokens { get; set; }
        public MinecraftProfile Profile { get; set; }

        public class TokensData
        {
            [JsonPropertyName("microsoft_access_token")]
            public string MicrosoftAccessToken { get; set; }
            
            [JsonPropertyName("microsoft_refresh_token")]
            public string MicrosoftRefreshToken { get; set; }
            
            [JsonPropertyName("xbl_token")]
            public string XblToken { get; set; }
            
            [JsonPropertyName("xsts_token")]
            public string XstsToken { get; set; }
            
            [JsonPropertyName("minecraft_access_token")]
            public string MinecraftAccessToken { get; set; }
            
            [JsonPropertyName("expires_in")]
            public int ExpiresIn { get; set; }
        }
    }

    public class MinecraftAuthenticator
    {
        private const string CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
        private const string SCOPE = "XboxLive.signin offline_access openid profile email";

        private const string DEVICE_CODE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
        private const string TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
        private const string XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
        private const string XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
        private const string MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
        private const string PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";

        private readonly HttpClient _httpClient;
        private readonly JsonSerializerOptions _jsonOptions;

        public MinecraftAuthenticator()
        {
            _httpClient = new HttpClient();
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("MinecraftAuthenticator/1.0");
            
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                PropertyNameCaseInsensitive = true
            };
        }

        public async Task<AuthResult> AuthenticateAsync()
        {
            Console.WriteLine("Minecraft Authentication - Device Code Flow\n");

            try
            {
                Console.WriteLine("[1/6] Requesting device code...");
                var deviceCodeResponse = await RequestDeviceCodeAsync();

                Console.WriteLine($"\nVisit this URL: {deviceCodeResponse.VerificationUri}");
                Console.WriteLine($"Enter this code: {deviceCodeResponse.UserCode}");
                Console.WriteLine("Waiting for authentication...");

                var tokenResponse = await PollForTokenAsync(deviceCodeResponse.DeviceCode, deviceCodeResponse.Interval);
                Console.WriteLine("\n[2/6] Polling for token...");

                var xblData = await AuthenticateWithXboxLiveAsync(tokenResponse.AccessToken);
                var xblToken = xblData.Token;
                var userHash = xblData.DisplayClaims.Xui[0].Uhs;
                Console.WriteLine("[3/6] Xbox Live authentication...");

                var xstsData = await AuthenticateWithXSTSAsync(xblToken);
                var xstsToken = xstsData.Token;
                Console.WriteLine("[4/6] XSTS authentication...");

                var mcTokenData = await LoginToMinecraftAsync(userHash, xstsToken);
                var mcAccessToken = mcTokenData.AccessToken;
                Console.WriteLine("[5/6] Minecraft login...");

                var profile = await GetMinecraftProfileAsync(mcAccessToken);
                Console.WriteLine("[6/6] Getting profile...");

                return new AuthResult
                {
                    Tokens = new AuthResult.TokensData
                    {
                        MicrosoftAccessToken = tokenResponse.AccessToken,
                        MicrosoftRefreshToken = tokenResponse.RefreshToken,
                        XblToken = xblToken,
                        XstsToken = xstsToken,
                        MinecraftAccessToken = mcAccessToken,
                        ExpiresIn = mcTokenData.ExpiresIn
                    },
                    Profile = profile
                };
            }
            catch (Exception e)
            {
                Console.WriteLine($"Authentication failed: {e.Message}");
                throw;
            }
        }

        private async Task<DeviceCodeResponse> RequestDeviceCodeAsync()
        {
            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "client_id", CLIENT_ID },
                { "scope", SCOPE }
            });

            var response = await _httpClient.PostAsync(DEVICE_CODE_URL, content);
            response.EnsureSuccessStatusCode();
            
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<DeviceCodeResponse>(json, _jsonOptions);
        }

        private async Task<TokenResponse> PollForTokenAsync(string deviceCode, int interval)
        {
            int pollInterval = Math.Max(interval, 5);
            int maxAttempts = 180;

            for (int attempt = 0; attempt < maxAttempts; attempt++)
            {
                try
                {
                    var content = new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
                        { "client_id", CLIENT_ID },
                        { "device_code", deviceCode }
                    });

                    var response = await _httpClient.PostAsync(TOKEN_URL, content);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var json = await response.Content.ReadAsStringAsync();
                        return JsonSerializer.Deserialize<TokenResponse>(json, _jsonOptions);
                    }
                    else
                    {
                        var errorJson = await response.Content.ReadAsStringAsync();
                        var errorObj = JsonSerializer.Deserialize<Dictionary<string, object>>(errorJson, _jsonOptions);
                        
                        if (errorObj != null && errorObj.ContainsKey("error") && errorObj["error"]?.ToString() == "authorization_pending")
                        {
                            await Task.Delay(pollInterval * 1000);
                            continue;
                        }
                        else
                        {
                            throw new Exception($"Token polling error: {errorJson}");
                        }
                    }
                }
                catch (Exception e)
                {
                    if (attempt == maxAttempts - 1)
                    {
                        throw new Exception("Authentication timeout - please try again", e);
                    }
                    await Task.Delay(pollInterval * 1000);
                }
            }

            throw new Exception("Authentication timeout - please try again");
        }

        private async Task<XboxAuthResponse> AuthenticateWithXboxLiveAsync(string accessToken)
        {
            var attempts = new[] { $"d={accessToken}", accessToken };

            foreach (var rpsTicket in attempts)
            {
                try
                {
                    var requestBody = new XboxAuthRequest
                    {
                        Properties = new XboxAuthRequest.PropertiesData
                        {
                            RpsTicket = rpsTicket
                        }
                    };

                    var json = JsonSerializer.Serialize(requestBody, _jsonOptions);
                    var content = new StringContent(json, Encoding.UTF8, "application/json");
                    
                    var request = new HttpRequestMessage(HttpMethod.Post, XBL_AUTH_URL)
                    {
                        Content = content
                    };
                    request.Headers.Add("Accept", "application/json");

                    var response = await _httpClient.SendAsync(request);
                    response.EnsureSuccessStatusCode();
                    
                    var responseJson = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<XboxAuthResponse>(responseJson, _jsonOptions);
                }
                catch
                {
                    continue;
                }
            }

            throw new Exception("Xbox Live authentication failed with both RPS ticket formats");
        }

        private async Task<XstsAuthResponse> AuthenticateWithXSTSAsync(string xblToken)
        {
            var requestBody = new XstsAuthRequest
            {
                Properties = new XstsAuthRequest.PropertiesData
                {
                    UserTokens = new List<string> { xblToken }
                }
            };

            var json = JsonSerializer.Serialize(requestBody, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            
            var request = new HttpRequestMessage(HttpMethod.Post, XSTS_AUTH_URL)
            {
                Content = content
            };
            request.Headers.Add("Accept", "application/json");

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<XstsAuthResponse>(responseJson, _jsonOptions);
        }

        private async Task<MinecraftLoginResponse> LoginToMinecraftAsync(string userHash, string xstsToken)
        {
            var requestBody = new MinecraftLoginRequest
            {
                IdentityToken = $"XBL3.0 x={userHash};{xstsToken}"
            };

            var json = JsonSerializer.Serialize(requestBody, _jsonOptions);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync(MC_LOGIN_URL, content);
            response.EnsureSuccessStatusCode();
            
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<MinecraftLoginResponse>(responseJson, _jsonOptions);
        }

        private async Task<MinecraftProfile> GetMinecraftProfileAsync(string mcAccessToken)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, PROFILE_URL);
            request.Headers.Add("Authorization", $"Bearer {mcAccessToken}");

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();
            
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<MinecraftProfile>(json, _jsonOptions);
        }
    }

    class Program
    {
        static async Task Main(string[] args)
        {
            try
            {
                var authenticator = new MinecraftAuthenticator();
                var result = await authenticator.AuthenticateAsync();

                Console.WriteLine("\nDone!");
                Console.WriteLine("You can use the following sample code to retrieve any field from the returned JSON:\n");
                Console.WriteLine("var authenticator = new MinecraftAuthenticator();");
                Console.WriteLine("var result = await authenticator.AuthenticateAsync();");
                Console.WriteLine("var accessToken = result.Tokens.MinecraftAccessToken;");
                Console.WriteLine("Console.WriteLine(accessToken);\n");
                Console.WriteLine("Below is the JSON returned from your recent login operation:\n");

                var options = new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                };
                Console.WriteLine(JsonSerializer.Serialize(result, options));
            }
            catch (Exception e)
            {
                Console.WriteLine($"Authentication failed: {e.Message}");
            }
        }
    }
}