@file:JvmName("Auth4KT")
package cn.gsfy

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

private const val CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
private const val SCOPE = "XboxLive.signin offline_access openid profile email"

private const val DEVICE_CODE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
private const val TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
private const val XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
private const val XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
private const val MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
private const val PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"

data class DeviceCodeResponse(
    @SerializedName("device_code") val deviceCode: String,
    @SerializedName("user_code") val userCode: String,
    @SerializedName("verification_uri") val verificationUri: String,
    @SerializedName("expires_in") val expiresIn: Int,
    @SerializedName("interval") val interval: Int,
    @SerializedName("message") val message: String
)

data class TokenResponse(
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("refresh_token") val refreshToken: String,
    @SerializedName("expires_in") val expiresIn: Int,
    @SerializedName("scope") val scope: String,
    @SerializedName("token_type") val tokenType: String
)

@Suppress("PropertyName")
data class XboxAuthRequest(
    val Properties: XboxAuthProperties,
    val RelyingParty: String = "http://auth.xboxlive.com",
    val TokenType: String = "JWT"
) {
    data class XboxAuthProperties(
        val AuthMethod: String = "RPS",
        val SiteName: String = "user.auth.xboxlive.com",
        val RpsTicket: String
    )
}

data class XboxAuthResponse(
    @SerializedName("Token") val token: String,
    @SerializedName("DisplayClaims") val displayClaims: DisplayClaims
) {
    data class DisplayClaims(
        @SerializedName("xui") val xui: List<Xui>
    ) {
        data class Xui(
            @SerializedName("uhs") val uhs: String
        )
    }
}

@Suppress("PropertyName")
data class XstsAuthRequest(
    val Properties: XstsAuthProperties,
    val RelyingParty: String = "rp://api.minecraftservices.com/",
    val TokenType: String = "JWT"
) {
    data class XstsAuthProperties(
        val SandboxId: String = "RETAIL",
        @SerializedName("UserTokens") val userTokens: List<String>
    )
}

data class XstsAuthResponse(
    @SerializedName("Token") val token: String
)

data class MinecraftLoginRequest(
    @SerializedName("identityToken") val identityToken: String
)

data class MinecraftLoginResponse(
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("expires_in") val expiresIn: Int
)

data class Skin(
    val id: String,
    val state: String,
    val url: String,
    @SerializedName("textureKey") val textureKey: String,
    val variant: String
)

data class Cape(
    val id: String,
    val state: String,
    val url: String,
    val alias: String
)

data class MinecraftProfile(
    val id: String,
    val name: String,
    val skins: List<Skin> = emptyList(),
    val capes: List<Cape> = emptyList(),
    @SerializedName("profileActions") val profileActions: Map<String, String> = emptyMap()
)

data class AuthResult(
    val tokens: Tokens,
    val profile: MinecraftProfile
) {
    data class Tokens(
        @SerializedName("microsoft_access_token") val microsoftAccessToken: String,
        @SerializedName("microsoft_refresh_token") val microsoftRefreshToken: String,
        @SerializedName("xbl_token") val xblToken: String,
        @SerializedName("xsts_token") val xstsToken: String,
        @SerializedName("minecraft_access_token") val minecraftAccessToken: String,
        @SerializedName("expires_in") val expiresIn: Int
    )
}

class MinecraftAuthenticator {
    private val client = OkHttpClient.Builder()
        .callTimeout(30, TimeUnit.SECONDS)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    private val gson = Gson()
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    suspend fun authenticate(): AuthResult {
        println("Minecraft Authentication - Device Code Flow\n")

        try {
            println("[1/6] Requesting device code...")
            val deviceCodeResponse = requestDeviceCode()

            println("\nVisit this URL: ${deviceCodeResponse.verificationUri}")
            println("Enter this code: ${deviceCodeResponse.userCode}")
            println("Waiting for authentication...")

            val tokenResponse = pollForToken(deviceCodeResponse.deviceCode, deviceCodeResponse.interval)
            println("\n[2/6] Polling for token...")

            val xblData = authenticateWithXboxLive(tokenResponse.accessToken)
            val xblToken = xblData.token
            val userHash = xblData.displayClaims.xui.first().uhs
            println("[3/6] Xbox Live authentication...")

            val xstsData = authenticateWithXSTS(xblToken)
            val xstsToken = xstsData.token
            println("[4/6] XSTS authentication...")

            val mcTokenData = loginToMinecraft(userHash, xstsToken)
            val mcAccessToken = mcTokenData.accessToken
            println("[5/6] Minecraft login...")

            val profile = getMinecraftProfile(mcAccessToken)
            println("[6/6] Getting profile...")
            return AuthResult(
                tokens = AuthResult.Tokens(
                    microsoftAccessToken = tokenResponse.accessToken,
                    microsoftRefreshToken = tokenResponse.refreshToken,
                    xblToken = xblToken,
                    xstsToken = xstsToken,
                    minecraftAccessToken = mcAccessToken,
                    expiresIn = mcTokenData.expiresIn
                ),
                profile = profile
            )

        } catch (e: Exception) {
            println("Authentication failed: ${e.message}")
            throw e
        }
    }

    private suspend fun requestDeviceCode(): DeviceCodeResponse = withContext(Dispatchers.IO) {
        val formBody = FormBody.Builder()
            .add("client_id", CLIENT_ID)
            .add("scope", SCOPE)
            .build()

        val request = Request.Builder()
            .url(DEVICE_CODE_URL)
            .post(formBody)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .build()

        executeRequest<DeviceCodeResponse>(request)
    }

    private suspend fun pollForToken(deviceCode: String, interval: Int): TokenResponse = withContext(Dispatchers.IO) {
        val pollInterval = (interval.coerceAtLeast(5)) * 1000L
        val maxAttempts = 180

        repeat(maxAttempts) { attempt ->
            try {
                val formBody = FormBody.Builder()
                    .add("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                    .add("client_id", CLIENT_ID)
                    .add("device_code", deviceCode)
                    .build()

                val request = Request.Builder()
                    .url(TOKEN_URL)
                    .post(formBody)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .build()

                val response = client.newCall(request).execute()

                if (response.isSuccessful) {
                    val body = response.body?.string() ?: ""
                    return@withContext gson.fromJson(body, TokenResponse::class.java)
                } else {
                    val errorBody = response.body?.string() ?: "{}"
                    val errorObj = gson.fromJson(errorBody, Map::class.java)

                    if (errorObj["error"] == "authorization_pending") {
                        delay(pollInterval)
                    } else {
                        throw IOException("Token polling error: $errorBody")
                    }
                }
            } catch (e: Exception) {
                if (attempt == maxAttempts - 1) {
                    throw IOException("Authentication timeout - please try again", e)
                }
                delay(pollInterval)
            }
        }

        throw IOException("Authentication timeout - please try again")
    }

    private suspend fun authenticateWithXboxLive(accessToken: String): XboxAuthResponse = withContext(Dispatchers.IO) {
        val attempts = listOf("d=$accessToken", accessToken)

        for (rpsTicket in attempts) {
            try {
                val requestBody = XboxAuthRequest(
                    Properties = XboxAuthRequest.XboxAuthProperties(RpsTicket = rpsTicket)
                )

                val jsonBody = gson.toJson(requestBody).toRequestBody(jsonMediaType)

                val request = Request.Builder()
                    .url(XBL_AUTH_URL)
                    .post(jsonBody)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .build()

                return@withContext executeRequest<XboxAuthResponse>(request)
            } catch (_: Exception) {
                continue
            }
        }

        throw IOException("Xbox Live authentication failed with both RPS ticket formats")
    }

    private suspend fun authenticateWithXSTS(xblToken: String): XstsAuthResponse = withContext(Dispatchers.IO) {
        val requestBody = XstsAuthRequest(
            Properties = XstsAuthRequest.XstsAuthProperties(
                userTokens = listOf(xblToken)
            )
        )

        val jsonBody = gson.toJson(requestBody).toRequestBody(jsonMediaType)

        val request = Request.Builder()
            .url(XSTS_AUTH_URL)
            .post(jsonBody)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .build()

        executeRequest<XstsAuthResponse>(request)
    }

    private suspend fun loginToMinecraft(userHash: String, xstsToken: String): MinecraftLoginResponse = withContext(Dispatchers.IO) {
        val requestBody = MinecraftLoginRequest(
            identityToken = "XBL3.0 x=$userHash;$xstsToken"
        )

        val jsonBody = gson.toJson(requestBody).toRequestBody(jsonMediaType)

        val request = Request.Builder()
            .url(MC_LOGIN_URL)
            .post(jsonBody)
            .header("Content-Type", "application/json")
            .build()

        executeRequest<MinecraftLoginResponse>(request)
    }

    private suspend fun getMinecraftProfile(mcAccessToken: String): MinecraftProfile = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(PROFILE_URL)
            .get()
            .header("Authorization", "Bearer $mcAccessToken")
            .build()

        executeRequest<MinecraftProfile>(request)
    }

    private inline fun <reified T> executeRequest(request: Request): T {
        val response = client.newCall(request).execute()

        if (!response.isSuccessful) {
            val errorBody = response.body?.string() ?: ""
            throw IOException("HTTP ${response.code}: ${response.message}. Body: $errorBody")
        }

        val body = response.body?.string() ?: ""

        if (body.isEmpty() && T::class != Unit::class) {
            throw IOException("Empty response body")
        }

        return gson.fromJson(body, T::class.java)
    }
}

fun main() = kotlinx.coroutines.runBlocking {
    val result = MinecraftAuthenticator().authenticate()
    val gsonPretty = com.google.gson.GsonBuilder()
        .setPrettyPrinting()
        .create()

    println("\nDone!")
    println("You can use the following sample code to retrieve any field from the returned JSON:\n")
    println("val authResult = MinecraftAuthenticator().authenticate()")
    println("val accessToken = authResult.tokens.minecraftAccessToken")
    println("println(accessToken)\n")
    println("Below is the JSON returned from your recent login operation:\n")

    println(gsonPretty.toJson(result))
}