Imports System
Imports System.Collections.Generic
Imports System.Net.Http
Imports System.Text
Imports System.Text.Json
Imports System.Text.Json.Serialization
Imports System.Threading.Tasks

Namespace Auth4VB
    Public Class DeviceCodeResponse
        <JsonPropertyName("device_code")>
        Public Property DeviceCode As String
        
        <JsonPropertyName("user_code")>
        Public Property UserCode As String
        
        <JsonPropertyName("verification_uri")>
        Public Property VerificationUri As String
        
        <JsonPropertyName("expires_in")>
        Public Property ExpiresIn As Integer
        
        <JsonPropertyName("interval")>
        Public Property Interval As Integer
        
        <JsonPropertyName("message")>
        Public Property Message As String
    End Class

    Public Class TokenResponse
        <JsonPropertyName("access_token")>
        Public Property AccessToken As String
        
        <JsonPropertyName("refresh_token")>
        Public Property RefreshToken As String
        
        <JsonPropertyName("expires_in")>
        Public Property ExpiresIn As Integer
        
        <JsonPropertyName("scope")>
        Public Property Scope As String
        
        <JsonPropertyName("token_type")>
        Public Property TokenType As String
    End Class

    Public Class XboxAuthRequest
        Public Property Properties As XboxAuthProperties
        Public Property RelyingParty As String = "http://auth.xboxlive.com"
        Public Property TokenType As String = "JWT"

        Public Class XboxAuthProperties
            Public Property AuthMethod As String = "RPS"
            Public Property SiteName As String = "user.auth.xboxlive.com"
            Public Property RpsTicket As String
        End Class
    End Class

    Public Class XboxAuthResponse
        <JsonPropertyName("Token")>
        Public Property Token As String
        
        <JsonPropertyName("DisplayClaims")>
        Public Property DisplayClaims As DisplayClaimsData

        Public Class DisplayClaimsData
            <JsonPropertyName("xui")>
            Public Property Xui As List(Of XuiData)

            Public Class XuiData
                <JsonPropertyName("uhs")>
                Public Property Uhs As String
            End Class
        End Class
    End Class

    Public Class XstsAuthRequest
        Public Property Properties As XstsAuthProperties
        Public Property RelyingParty As String = "rp://api.minecraftservices.com/"
        Public Property TokenType As String = "JWT"

        Public Class XstsAuthProperties
            Public Property SandboxId As String = "RETAIL"
            
            <JsonPropertyName("UserTokens")>
            Public Property UserTokens As List(Of String)
        End Class
    End Class

    Public Class XstsAuthResponse
        <JsonPropertyName("Token")>
        Public Property Token As String
    End Class

    Public Class MinecraftLoginRequest
        <JsonPropertyName("identityToken")>
        Public Property IdentityToken As String
    End Class

    Public Class MinecraftLoginResponse
        <JsonPropertyName("access_token")>
        Public Property AccessToken As String
        
        <JsonPropertyName("expires_in")>
        Public Property ExpiresIn As Integer
    End Class

    Public Class Skin
        Public Property Id As String
        Public Property State As String
        Public Property Url As String
        
        <JsonPropertyName("textureKey")>
        Public Property TextureKey As String
        Public Property Variant As String
    End Class

    Public Class Cape
        Public Property Id As String
        Public Property State As String
        Public Property Url As String
        Public Property Alias As String
    End Class

    Public Class MinecraftProfile
        Public Property Id As String
        Public Property Name As String
        Public Property Skins As List(Of Skin) = New List(Of Skin)()
        Public Property Capes As List(Of Cape) = New List(Of Cape)()
        
        <JsonPropertyName("profileActions")>
        Public Property ProfileActions As Dictionary(Of String, String) = New Dictionary(Of String, String)()
    End Class

    Public Class AuthResult
        Public Property Tokens As TokensData
        Public Property Profile As MinecraftProfile

        Public Class TokensData
            <JsonPropertyName("microsoft_access_token")>
            Public Property MicrosoftAccessToken As String
            
            <JsonPropertyName("microsoft_refresh_token")>
            Public Property MicrosoftRefreshToken As String
            
            <JsonPropertyName("xbl_token")>
            Public Property XblToken As String
            
            <JsonPropertyName("xsts_token")>
            Public Property XstsToken As String
            
            <JsonPropertyName("minecraft_access_token")>
            Public Property MinecraftAccessToken As String
            
            <JsonPropertyName("expires_in")>
            Public Property ExpiresIn As Integer
        End Class
    End Class

    Public Class MinecraftAuthenticator
        Private Const CLIENT_ID As String = "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
        Private Const SCOPE As String = "XboxLive.signin offline_access openid profile email"

        Private Const DEVICE_CODE_URL As String = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
        Private Const TOKEN_URL As String = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
        Private Const XBL_AUTH_URL As String = "https://user.auth.xboxlive.com/user/authenticate"
        Private Const XSTS_AUTH_URL As String = "https://xsts.auth.xboxlive.com/xsts/authorize"
        Private Const MC_LOGIN_URL As String = "https://api.minecraftservices.com/authentication/login_with_xbox"
        Private Const PROFILE_URL As String = "https://api.minecraftservices.com/minecraft/profile"

        Private ReadOnly _httpClient As HttpClient
        Private ReadOnly _jsonOptions As JsonSerializerOptions

        Public Sub New()
            _httpClient = New HttpClient()
            _httpClient.Timeout = TimeSpan.FromSeconds(30)
            _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("MinecraftAuthenticator/1.0")
            
            _jsonOptions = New JsonSerializerOptions With {
                .PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                .PropertyNameCaseInsensitive = True
            }
        End Sub

        Public Async Function AuthenticateAsync() As Task(Of AuthResult)
            Console.WriteLine("Minecraft Authentication - Device Code Flow" & vbCrLf)

            Try
                Console.WriteLine("[1/6] Requesting device code...")
                Dim deviceCodeResponse = Await RequestDeviceCodeAsync()

                Console.WriteLine(vbCrLf & "Visit this URL: " & deviceCodeResponse.VerificationUri)
                Console.WriteLine("Enter this code: " & deviceCodeResponse.UserCode)
                Console.WriteLine("Waiting for authentication...")

                Dim tokenResponse = Await PollForTokenAsync(deviceCodeResponse.DeviceCode, deviceCodeResponse.Interval)
                Console.WriteLine(vbCrLf & "[2/6] Polling for token...")

                Dim xblData = Await AuthenticateWithXboxLiveAsync(tokenResponse.AccessToken)
                Dim xblToken = xblData.Token
                Dim userHash = xblData.DisplayClaims.Xui(0).Uhs
                Console.WriteLine("[3/6] Xbox Live authentication...")

                Dim xstsData = Await AuthenticateWithXSTSAsync(xblToken)
                Dim xstsToken = xstsData.Token
                Console.WriteLine("[4/6] XSTS authentication...")

                Dim mcTokenData = Await LoginToMinecraftAsync(userHash, xstsToken)
                Dim mcAccessToken = mcTokenData.AccessToken
                Console.WriteLine("[5/6] Minecraft login...")

                Dim profile = Await GetMinecraftProfileAsync(mcAccessToken)
                Console.WriteLine("[6/6] Getting profile...")

                Return New AuthResult With {
                    .Tokens = New AuthResult.TokensData With {
                        .MicrosoftAccessToken = tokenResponse.AccessToken,
                        .MicrosoftRefreshToken = tokenResponse.RefreshToken,
                        .XblToken = xblToken,
                        .XstsToken = xstsToken,
                        .MinecraftAccessToken = mcAccessToken,
                        .ExpiresIn = mcTokenData.ExpiresIn
                    },
                    .Profile = profile
                }
            Catch e As Exception
                Console.WriteLine("Authentication failed: " & e.Message)
                Throw
            End Try
        End Function

        Private Async Function RequestDeviceCodeAsync() As Task(Of DeviceCodeResponse)
            Dim content = New FormUrlEncodedContent(New Dictionary(Of String, String) From {
                {"client_id", CLIENT_ID},
                {"scope", SCOPE}
            })

            Dim response = Await _httpClient.PostAsync(DEVICE_CODE_URL, content)
            response.EnsureSuccessStatusCode()
            
            Dim json = Await response.Content.ReadAsStringAsync()
            Return JsonSerializer.Deserialize(Of DeviceCodeResponse)(json, _jsonOptions)
        End Function

        Private Async Function PollForTokenAsync(deviceCode As String, interval As Integer) As Task(Of TokenResponse)
            Dim pollInterval = Math.Max(interval, 5)
            Dim maxAttempts = 180

            For attempt As Integer = 0 To maxAttempts - 1
                Try
                    Dim content = New FormUrlEncodedContent(New Dictionary(Of String, String) From {
                        {"grant_type", "urn:ietf:params:oauth:grant-type:device_code"},
                        {"client_id", CLIENT_ID},
                        {"device_code", deviceCode}
                    })

                    Dim response = Await _httpClient.PostAsync(TOKEN_URL, content)
                    
                    If response.IsSuccessStatusCode Then
                        Dim json = Await response.Content.ReadAsStringAsync()
                        Return JsonSerializer.Deserialize(Of TokenResponse)(json, _jsonOptions)
                    Else
                        Dim errorJson = Await response.Content.ReadAsStringAsync()
                        Dim errorObj = JsonSerializer.Deserialize(Of Dictionary(Of String, Object))(errorJson, _jsonOptions)
                        
                        If errorObj IsNot Nothing AndAlso errorObj.ContainsKey("error") AndAlso errorObj("error")?.ToString() = "authorization_pending" Then
                            Await Task.Delay(pollInterval * 1000)
                            Continue For
                        Else
                            Throw New Exception("Token polling error: " & errorJson)
                        End If
                    End If
                Catch e As Exception
                    If attempt = maxAttempts - 1 Then
                        Throw New Exception("Authentication timeout - please try again", e)
                    End If
                    Await Task.Delay(pollInterval * 1000)
                End Try
            Next

            Throw New Exception("Authentication timeout - please try again")
        End Function

        Private Async Function AuthenticateWithXboxLiveAsync(accessToken As String) As Task(Of XboxAuthResponse)
            Dim attempts = {"d=" & accessToken, accessToken}

            For Each rpsTicket In attempts
                Try
                    Dim requestBody = New XboxAuthRequest With {
                        .Properties = New XboxAuthRequest.XboxAuthProperties With {
                            .RpsTicket = rpsTicket
                        }
                    }

                    Dim json = JsonSerializer.Serialize(requestBody, _jsonOptions)
                    Dim content = New StringContent(json, Encoding.UTF8, "application/json")
                    
                    Dim request = New HttpRequestMessage(HttpMethod.Post, XBL_AUTH_URL) With {
                        .Content = content
                    }
                    request.Headers.Add("Accept", "application/json")

                    Dim response = Await _httpClient.SendAsync(request)
                    response.EnsureSuccessStatusCode()
                    
                    Dim responseJson = Await response.Content.ReadAsStringAsync()
                    Return JsonSerializer.Deserialize(Of XboxAuthResponse)(responseJson, _jsonOptions)
                Catch
                    Continue For
                End Try
            Next

            Throw New Exception("Xbox Live authentication failed with both RPS ticket formats")
        End Function

        Private Async Function AuthenticateWithXSTSAsync(xblToken As String) As Task(Of XstsAuthResponse)
            Dim requestBody = New XstsAuthRequest With {
                .Properties = New XstsAuthRequest.XstsAuthProperties With {
                    .UserTokens = New List(Of String) From {xblToken}
                }
            }

            Dim json = JsonSerializer.Serialize(requestBody, _jsonOptions)
            Dim content = New StringContent(json, Encoding.UTF8, "application/json")
            
            Dim request = New HttpRequestMessage(HttpMethod.Post, XSTS_AUTH_URL) With {
                .Content = content
            }
            request.Headers.Add("Accept", "application/json")

            Dim response = Await _httpClient.SendAsync(request)
            response.EnsureSuccessStatusCode()
            
            Dim responseJson = Await response.Content.ReadAsStringAsync()
            Return JsonSerializer.Deserialize(Of XstsAuthResponse)(responseJson, _jsonOptions)
        End Function

        Private Async Function LoginToMinecraftAsync(userHash As String, xstsToken As String) As Task(Of MinecraftLoginResponse)
            Dim requestBody = New MinecraftLoginRequest With {
                .IdentityToken = "XBL3.0 x=" & userHash & ";" & xstsToken
            }

            Dim json = JsonSerializer.Serialize(requestBody, _jsonOptions)
            Dim content = New StringContent(json, Encoding.UTF8, "application/json")

            Dim response = Await _httpClient.PostAsync(MC_LOGIN_URL, content)
            response.EnsureSuccessStatusCode()
            
            Dim responseJson = Await response.Content.ReadAsStringAsync()
            Return JsonSerializer.Deserialize(Of MinecraftLoginResponse)(responseJson, _jsonOptions)
        End Function

        Private Async Function GetMinecraftProfileAsync(mcAccessToken As String) As Task(Of MinecraftProfile)
            Dim request = New HttpRequestMessage(HttpMethod.Get, PROFILE_URL)
            request.Headers.Add("Authorization", "Bearer " & mcAccessToken)

            Dim response = Await _httpClient.SendAsync(request)
            response.EnsureSuccessStatusCode()
            
            Dim json = Await response.Content.ReadAsStringAsync()
            Return JsonSerializer.Deserialize(Of MinecraftProfile)(json, _jsonOptions)
        End Function
    End Class

    Module Program
        Async Function MainAsync() As Task
            Try
                Dim authenticator = New MinecraftAuthenticator()
                Dim result = Await authenticator.AuthenticateAsync()

                Console.WriteLine(vbCrLf & "Done!")
                Console.WriteLine("You can use the following sample code to retrieve any field from the returned JSON:" & vbCrLf)
                Console.WriteLine("Dim authenticator = New MinecraftAuthenticator()")
                Console.WriteLine("Dim result = Await authenticator.AuthenticateAsync()")
                Console.WriteLine("Dim accessToken = result.Tokens.MinecraftAccessToken")
                Console.WriteLine("Console.WriteLine(accessToken)" & vbCrLf)
                Console.WriteLine("Below is the JSON returned from your recent login operation:" & vbCrLf)

                Dim options = New JsonSerializerOptions With {
                    .WriteIndented = True,
                    .PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                }
                Console.WriteLine(JsonSerializer.Serialize(result, options))
            Catch e As Exception
                Console.WriteLine("Authentication failed: " & e.Message)
            End Try
        End Function

        Sub Main()
            MainAsync().GetAwaiter().GetResult()
        End Sub
    End Module
End Namespace