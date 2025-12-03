using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

namespace MinecraftAuth
{
    public class Program
    {
        private const string CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab";
        private const string REDIRECT_URI = "http://localhost:3000/proxy/";
        private const string SCOPE = "XboxLive.signin offline_access";
        private const string AUTHORIZE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
        private const string TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
        private const string XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate";
        private const string XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize";
        private const string MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox";
        private const string MC_STORE_URL = "https://api.minecraftservices.com/entitlements/mcstore";
        private const string PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile";
        private const int PORT = 3000;

        private static readonly string CODE_VERIFIER = "W6i3P9qL8zX2rV5sT1uY4aB7cD0eF3gH6jK9mN2pQ5s";
        private static readonly string CODE_CHALLENGE = GenerateCodeChallenge(CODE_VERIFIER);
        private static readonly ConcurrentDictionary<string, AuthData> authDataMap = new();
        private static readonly HttpClient httpClient = new HttpClient();

        static async Task Main(string[] args)
        {
            var host = CreateWebHostBuilder().Build();
            
            Console.WriteLine($"Server started on port: {PORT}");
            Console.WriteLine("Please visit the following URL for authorization:");
            Console.WriteLine(GenerateAuthorizeUrl());
            Console.WriteLine("Waiting for authorization...");
            Console.WriteLine("\nPress Ctrl+C to exit...");

            await host.RunAsync();
        }

        private static IHostBuilder CreateWebHostBuilder() =>
            Host.CreateDefaultBuilder()
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseUrls($"http://localhost:{PORT}");
                    webBuilder.Configure(app =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapGet("/proxy/", HandleOAuthCallback);
                            endpoints.MapGet("/data/{uuid}", HandleDataRequest);
                        });
                    });
                });

        private static async Task HandleOAuthCallback(HttpContext context)
        {
            var authCode = context.Request.Query["code"];
            
            if (string.IsNullOrEmpty(authCode))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Authorization code not received");
                return;
            }

            _ = Task.Run(() => HandleAuthentication(authCode));
            
            context.Response.StatusCode = 200;
            await context.Response.WriteAsync("Authentication in progress... Please check console for results.");
        }

        private static async Task HandleDataRequest(HttpContext context)
        {
            var uuid = context.Request.RouteValues["uuid"] as string;
            uuid = uuid?.Replace(".json", "");

            if (authDataMap.TryGetValue(uuid, out var authData))
            {
                context.Response.ContentType = "application/json";
                await JsonSerializer.SerializeAsync(context.Response.Body, authData, 
                    new JsonSerializerOptions { WriteIndented = true });
            }
            else
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("Data not found or expired");
            }
        }

        private static async void HandleAuthentication(string authCode)
        {
            try
            {
                Console.WriteLine("[1/6] Exchanging authorization code for Microsoft token...");
                var tokenData = await ExchangeCodeForToken(authCode);
                var accessToken = tokenData.GetProperty("access_token").GetString();

                Console.WriteLine("[2/6] Xbox Live authentication...");
                var xblData = await AuthenticateXboxLive(accessToken);
                var xblToken = xblData.GetProperty("Token").GetString();
                var userHash = xblData.GetProperty("DisplayClaims").GetProperty("xui")[0]
                    .GetProperty("uhs").GetString();

                Console.WriteLine("[3/6] XSTS authentication...");
                var xstsData = await AuthenticateXSTS(xblToken);
                var xstsToken = xstsData.GetProperty("Token").GetString();

                Console.WriteLine("[4/6] Getting Minecraft access token...");
                var mcTokenData = await LoginWithXbox(userHash, xstsToken);
                var mcAccessToken = mcTokenData.GetProperty("access_token").GetString();

                Console.WriteLine("[5/6] Checking game ownership...");
                var entitlements = await CheckGameOwnership(mcAccessToken);
                if (!entitlements.TryGetProperty("items", out var items) || 
                    items.GetArrayLength() == 0)
                {
                    throw new Exception("This account does not own Minecraft");
                }

                Console.WriteLine("[6/6] Getting Minecraft profile...");
                var profile = await GetMinecraftProfile(mcAccessToken);
                var playerUuid = profile.GetProperty("id").GetString();

                var authData = new AuthData
                {
                    Tokens = new Tokens
                    {
                        MicrosoftAccessToken = accessToken,
                        MicrosoftRefreshToken = tokenData.GetProperty("refresh_token").GetString(),
                        XblToken = xblToken,
                        XstsToken = xstsToken,
                        MinecraftAccessToken = mcAccessToken,
                        ExpiresIn = tokenData.GetProperty("expires_in").GetInt32()
                    },
                    Profile = profile,
                    Pkce = new PKCEData
                    {
                        CodeVerifier = CODE_VERIFIER,
                        CodeChallenge = CODE_CHALLENGE
                    }
                };

                authDataMap[playerUuid] = authData;

                Console.WriteLine("\nDone.");
                Console.WriteLine("\nData access URL:");
                Console.WriteLine($"http://localhost:{PORT}/data/{playerUuid}.json");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        private static string GenerateAuthorizeUrl()
        {
            var parameters = new Dictionary<string, string>
            {
                ["client_id"] = CLIENT_ID,
                ["response_type"] = "code",
                ["redirect_uri"] = REDIRECT_URI,
                ["scope"] = SCOPE,
                ["code_challenge"] = CODE_CHALLENGE,
                ["code_challenge_method"] = "S256",
                ["prompt"] = "select_account"
            };

            var query = string.Join("&", parameters.Select(p => 
                $"{WebUtility.UrlEncode(p.Key)}={WebUtility.UrlEncode(p.Value)}"));
            
            return $"{AUTHORIZE_URL}?{query}";
        }

        private static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Convert.ToBase64String(hash)
                .Replace("+", "-")
                .Replace("/", "_")
                .Replace("=", "");
        }

        private static async Task<JsonDocument> ExchangeCodeForToken(string authCode)
        {
            var parameters = new Dictionary<string, string>
            {
                ["client_id"] = CLIENT_ID,
                ["code"] = authCode,
                ["redirect_uri"] = REDIRECT_URI,
                ["grant_type"] = "authorization_code",
                ["code_verifier"] = CODE_VERIFIER
            };

            var content = new FormUrlEncodedContent(parameters);
            var response = await httpClient.PostAsync(TOKEN_URL, content);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                throw new Exception($"Token exchange failed: {error}");
            }

            var json = await response.Content.ReadAsStringAsync();
            return JsonDocument.Parse(json);
        }

        private static async Task<JsonDocument> AuthenticateXboxLive(string accessToken)
        {
            var rpsTickets = new[] { $"d={accessToken}", accessToken };

            foreach (var rpsTicket in rpsTickets)
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
                    return JsonDocument.Parse(responseJson);
                }
            }

            throw new Exception("Xbox Live authentication failed");
        }

        private static async Task<JsonDocument> AuthenticateXSTS(string xblToken)
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
            return JsonDocument.Parse(responseJson);
        }

        private static async Task<JsonDocument> LoginWithXbox(string userHash, string xstsToken)
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
            return JsonDocument.Parse(responseJson);
        }

        private static async Task<JsonDocument> CheckGameOwnership(string mcAccessToken)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, MC_STORE_URL);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", mcAccessToken);

            var response = await httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                throw new Exception($"Game ownership check failed: {error}");
            }

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonDocument.Parse(responseJson);
        }

        private static async Task<JsonDocument> GetMinecraftProfile(string mcAccessToken)
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
            return JsonDocument.Parse(responseJson);
        }
    }

    public class AuthData
    {
        public Tokens Tokens { get; set; }
        public JsonDocument Profile { get; set; }
        public PKCEData Pkce { get; set; }
    }

    public class Tokens
    {
        public string MicrosoftAccessToken { get; set; }
        public string MicrosoftRefreshToken { get; set; }
        public string XblToken { get; set; }
        public string XstsToken { get; set; }
        public string MinecraftAccessToken { get; set; }
        public int ExpiresIn { get; set; }
    }

    public class PKCEData
    {
        public string CodeVerifier { get; set; }
        public string CodeChallenge { get; set; }
    }
}