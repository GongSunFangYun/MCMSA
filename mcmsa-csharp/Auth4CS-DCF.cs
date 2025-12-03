using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MinecraftAuth.DeviceCode
{
    public class Program
    {
        // Configuration constants
        private const string CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
        private const string SCOPE = "XboxLive.signin offline_access openid profile email";
        
        // OAuth endpoints
        private const string DEVICE_CODE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
        private const string TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
        private const string XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
        private const string XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
        private const string MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
        private const string MC_STORE_URL = "https://api.minecraftservices.com/entitlements/mcstore";
        private const string PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";
        
        // Polling configuration
        private const int DEFAULT_POLL_INTERVAL = 5; // seconds
        private const int MAX_POLL_ATTEMPTS = 180; // 15 minutes if interval is 5 seconds
        
        private static readonly HttpClient httpClient = new HttpClient();

        public static async Task Main(string[] args)
        {
            Console.WriteLine("Minecraft Authentication - Device Code Flow\n");
            
            try
            {
                await StartDeviceAuth();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
                Environment.Exit(1);
            }
        }

        private static async Task StartDeviceAuth()
        {
            // 1. Request device code
            Console.WriteLine("[1/7] Requesting device code...");
            var deviceCodeResponse = await RequestDeviceCode();
            
            Console.WriteLine($"\nPlease visit: {deviceCodeResponse.VerificationUri}");
            Console.WriteLine($"Enter this code: {deviceCodeResponse.UserCode}");
            Console.WriteLine("\nWaiting for authentication...");
            
            // 2. Poll for access token
            Console.WriteLine("[2/7] Polling for token...");
            var tokenResponse = await PollForToken(
                deviceCodeResponse.DeviceCode, 
                deviceCodeResponse.Interval > 0 ? deviceCodeResponse.Interval : DEFAULT_POLL_INTERVAL);
            
            Console.WriteLine("[3/7] Microsoft token obtained");
            
            // 3. Xbox Live authentication
            Console.WriteLine("[4/7] Xbox Live authentication...");
            var xblData = await AuthenticateXboxLive(tokenResponse.AccessToken);
            var xblToken = xblData.Token;
            var userHash = xblData.DisplayClaims.Xui[0].Uhs;
            
            // 4. XSTS authentication
            Console.WriteLine("[5/7] XSTS authentication...");
            var xstsData = await AuthenticateXSTS(xblToken);
            var xstsToken = xstsData.Token;
            
            // 5. Minecraft login
            Console.WriteLine("[6/7] Minecraft login...");
            var mcTokenData = await LoginToMinecraft(userHash, xstsToken);
            var mcAccessToken = mcTokenData.AccessToken;
            
            // 6. Check game ownership (optional)
            Console.WriteLine("[6.5/7] Checking game ownership...");
            var ownsGame = await CheckGameOwnership(mcAccessToken);
            if (!ownsGame)
            {
                throw new Exception("This account does not own Minecraft");
            }
            
            // 7. Get Minecraft profile
            Console.WriteLine("[7/7] Getting Minecraft profile...");
            var profile = await GetMinecraftProfile(mcAccessToken);
            
            // Build authentication result
            var authResult = BuildAuthResult(profile, tokenResponse, xblToken, xstsToken, mcTokenData);
            
            // Output result
            PrintAuthResult(authResult);
        }

        private static async Task<DeviceCodeResponse> RequestDeviceCode()
        {
            var parameters = new Dictionary<string, string>
            {
                ["client_id"] = CLIENT_ID,
                ["scope"] = SCOPE
            };

            var content = new FormUrlEncodedContent(parameters);
            var response = await httpClient.PostAsync(DEVICE_CODE_URL, content);
            
            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                throw new Exception($"Device code request failed: {error}");
            }
            
            var json = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<DeviceCodeResponse>(json);
        }

        private static async Task<TokenResponse> PollForToken(string deviceCode, int interval)
        {
            var parameters = new Dictionary<string, string>
            {
                ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                ["client_id"] = CLIENT_ID,
                ["device_code"] = deviceCode
            };

            for (int attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++)
            {
                try
                {
                    var content = new FormUrlEncodedContent(parameters);
                    var response = await httpClient.PostAsync(TOKEN_URL, content);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var json = await response.Content.ReadAsStringAsync();
                        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json);
                        
                        if (!string.IsNullOrEmpty(tokenResponse.AccessToken))
                        {
                            Console.Write(".");
                            return tokenResponse;
                        }
                    }
                    else
                    {
                        var errorJson = await response.Content.ReadAsStringAsync();
                        var errorDoc = JsonDocument.Parse(errorJson);
                        
                        if (errorDoc.RootElement.TryGetProperty("error", out var errorProp) &&
                            errorProp.GetString() == "authorization_pending")
                        {
                            Console.Write(".");
                            await Task.Delay(interval * 1000);
                            continue;
                        }
                    }
                }
                catch
                {
                    // Continue polling on network errors
                }
                
                await Task.Delay(interval * 1000);
            }
            
            throw new Exception("Authentication timeout - please try again");
        }

        private static async Task<XboxAuthResponse> AuthenticateXboxLive(string accessToken)
        {
            // Try two formats of RPS ticket
            var rpsTickets = new[] { $"d={accessToken}", accessToken };

            foreach (var rpsTicket in rpsTickets)
            {
                try
                {
                    var data = new
                    {
                        Properties = new
                        {
                            AuthMethod = "RPS",
                            SiteName = "user.auth.xboxlive.com",
                            RpsTicket = rpsTicket
                        },
                        RelyingParty = "http://auth.xboxlive.com",
                        TokenType = "JWT"
                    };

                    var json = JsonSerializer.Serialize(data);
                    var content = new StringContent(json, Encoding.UTF8, "application/json");
                    
                    var request = new HttpRequestMessage(HttpMethod.Post, XBL_AUTH_URL)
                    {
                        Content = content
                    };
                    request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                    
                    var response = await httpClient.SendAsync(request);
                    
                    if (response.IsSuccessStatusCode)
                    {
                        var responseJson = await response.Content.ReadAsStringAsync();
                        return JsonSerializer.Deserialize<XboxAuthResponse>(responseJson);
                    }
                }
                catch
                {
                    // Try next format
                }
            }
            
            throw new Exception("Xbox Live authentication failed");
        }

        private static async Task<XSTSResponse> AuthenticateXSTS(string xblToken)
        {
            var data = new
            {
                Properties = new
                {
                    SandboxId = "RETAIL",
                    UserTokens = new[] { xblToken }
                },
                RelyingParty = "rp://api.minecraftservices.com/",
                TokenType = "JWT"
            };

            var json = JsonSerializer.Serialize(data);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            
            var request = new HttpRequestMessage(HttpMethod.Post, XSTS_AUTH_URL)
            {
                Content = content
            };
            request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
            
            var response = await httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                throw new Exception($"XSTS authentication failed: {error}");
            }
            
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<XSTSResponse>(responseJson);
        }

        private static async Task<MinecraftTokenResponse> LoginToMinecraft(string userHash, string xstsToken)
        {
            var data = new
            {
                identityToken = $"XBL3.0 x={userHash};{xstsToken}"
            };

            var json = JsonSerializer.Serialize(data);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await httpClient.PostAsync(MC_LOGIN_URL, content);
            
            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                throw new Exception($"Minecraft login failed: {error}");
            }
            
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<MinecraftTokenResponse>(responseJson);
        }

        private static async Task<bool> CheckGameOwnership(string mcAccessToken)
        {
            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, MC_STORE_URL);
                request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", mcAccessToken);
                
                var response = await httpClient.SendAsync(request);
                
                if (!response.IsSuccessStatusCode)
                {
                    return false;
                }
                
                var responseJson = await response.Content.ReadAsStringAsync();
                var doc = JsonDocument.Parse(responseJson);
                
                if (doc.RootElement.TryGetProperty("items", out var items) && 
                    items.GetArrayLength() > 0)
                {
                    return true;
                }
                
                return false;
            }
            catch
            {
                return false;
            }
        }

        private static async Task<MinecraftProfile> GetMinecraftProfile(string mcAccessToken)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, PROFILE_URL);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", mcAccessToken);
            
            var response = await httpClient.SendAsync(request);
            
            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                throw new Exception($"Profile fetch failed: {error}");
            }
            
            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<MinecraftProfile>(responseJson);
        }

        private static AuthResult BuildAuthResult(
            MinecraftProfile profile, 
            TokenResponse tokenResponse, 
            string xblToken, 
            string xstsToken, 
            MinecraftTokenResponse mcTokenData)
        {
            return new AuthResult
            {
                Timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                Player = new PlayerInfo
                {
                    Id = profile.Id,
                    Name = profile.Name
                },
                Tokens = new TokenInfo
                {
                    Microsoft = new MicrosoftTokens
                    {
                        AccessToken = tokenResponse.AccessToken,
                        RefreshToken = tokenResponse.RefreshToken,
                        ExpiresIn = tokenResponse.ExpiresIn,
                        Scope = tokenResponse.Scope
                    },
                    Xbox = new XboxTokens
                    {
                        XblToken = xblToken,
                        XstsToken = xstsToken
                    },
                    Minecraft = new MinecraftTokens
                    {
                        AccessToken = mcTokenData.AccessToken,
                        ExpiresIn = mcTokenData.ExpiresIn
                    }
                },
                Profile = profile
            };
        }

        private static void PrintAuthResult(AuthResult result)
        {
            Console.WriteLine("\n--- AUTHENTICATION COMPLETE ---");
            Console.WriteLine($"Player: {result.Player.Name}");
            Console.WriteLine($"UUID: {result.Player.Id}");
            Console.WriteLine("\n--- AUTHENTICATION DATA ---");
            
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            var json = JsonSerializer.Serialize(result, jsonOptions);
            Console.WriteLine(json);
            
            Console.WriteLine("\n--- TOKEN SUMMARY ---");
            Console.WriteLine($"Minecraft Access Token: {result.Tokens.Minecraft.AccessToken.Substring(0, Math.Min(30, result.Tokens.Minecraft.AccessToken.Length))}...");
            Console.WriteLine($"Microsoft Refresh Token: {result.Tokens.Microsoft.RefreshToken.Substring(0, Math.Min(30, result.Tokens.Microsoft.RefreshToken.Length))}...");
            Console.WriteLine("\n--- END ---");
        }
    }

    // Response model classes
    public class DeviceCodeResponse
    {
        public string DeviceCode { get; set; }
        public string UserCode { get; set; }
        public string VerificationUri { get; set; }
        public int ExpiresIn { get; set; }
        public int Interval { get; set; }
        public string Message { get; set; }
    }

    public class TokenResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
        public string Scope { get; set; }
        public string TokenType { get; set; }
    }

    public class XboxAuthResponse
    {
        public string Token { get; set; }
        public DisplayClaims DisplayClaims { get; set; }
    }

    public class DisplayClaims
    {
        public List<Xui> Xui { get; set; }
    }

    public class Xui
    {
        public string Uhs { get; set; }
    }

    public class XSTSResponse
    {
        public string Token { get; set; }
    }

    public class MinecraftTokenResponse
    {
        public string AccessToken { get; set; }
        public int ExpiresIn { get; set; }
    }

    public class MinecraftProfile
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }

    public class AuthResult
    {
        public string Timestamp { get; set; }
        public PlayerInfo Player { get; set; }
        public TokenInfo Tokens { get; set; }
        public MinecraftProfile Profile { get; set; }
    }

    public class PlayerInfo
    {
        public string Id { get; set; }
        public string Name { get; set; }
    }

    public class TokenInfo
    {
        public MicrosoftTokens Microsoft { get; set; }
        public XboxTokens Xbox { get; set; }
        public MinecraftTokens Minecraft { get; set; }
    }

    public class MicrosoftTokens
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int ExpiresIn { get; set; }
        public string Scope { get; set; }
    }

    public class XboxTokens
    {
        public string XblToken { get; set; }
        public string XstsToken { get; set; }
    }

    public class MinecraftTokens
    {
        public string AccessToken { get; set; }
        public int ExpiresIn { get; set; }
    }
}