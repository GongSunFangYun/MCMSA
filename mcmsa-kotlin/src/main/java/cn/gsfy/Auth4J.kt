@file:Suppress("PropertyName")

package cn.gsfy// MinecraftAuthentication.kt
import com.sun.net.httpserver.HttpServer
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import kotlin.concurrent.thread
import kotlin.math.ceil

@Serializable
data class AuthData(
    val tokens: Tokens,
    val profile: JsonObject,
    val pkce: PKCE
) {
    @Serializable
    data class Tokens(
        val microsoft_access_token: String,
        val microsoft_refresh_token: String,
        val xbl_token: String,
        val xsts_token: String,
        val minecraft_access_token: String,
        val expires_in: Int
    )

    @Serializable
    data class PKCE(
        val code_verifier: String,
        val code_challenge: String
    )
}

@Serializable
data class TokenResponse(
    val access_token: String,
    val refresh_token: String,
    val expires_in: Int
)

class MinecraftAuthentication {

    companion object {
        private const val CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
        private const val REDIRECT_URI = "http://localhost:3000/proxy/"
        private const val SCOPE = "XboxLive.signin offline_access"

        // OAuth endpoints
        private const val AUTHORIZE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
        private const val TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
        private const val XBL_AUTH_URL = "https://user.auth.xboxlive.com/user/authenticate"
        private const val XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
        private const val MC_LOGIN_URL = "https://api.minecraftservices.com/authentication/login_with_xbox"
        private const val MC_ENTITLEMENTS_URL = "https://api.minecraftservices.com/entitlements/mcstore"
        private const val PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"

        // PKCE - 使用固定值
        private const val FIXED_CODE_VERIFIER = "W6i3P9qL8zX2rV5sT1uY4aB7cD0eF3gH6jK9mN2pQ5s"
        private const val CODE_VERIFIER = FIXED_CODE_VERIFIER
        private val CODE_CHALLENGE = generateCodeChallenge(CODE_VERIFIER)

        private const val PORT = 3000
        private val httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build()
        private val json = Json {
            prettyPrint = true
            ignoreUnknownKeys = true
        }

        // Store authentication data
        private val authDataMap = ConcurrentHashMap<String, AuthData>()
        private lateinit var server: HttpServer

        @JvmStatic
        fun main(args: Array<String>) {
            startServer()
        }

        private fun startServer() {
            server = HttpServer.create(InetSocketAddress(PORT), 0)

            // Handle OAuth callback
            server.createContext("/proxy/") { exchange ->
                try {
                    val requestUri = exchange.requestURI
                    val query = requestUri.query

                    val queryParams = parseQuery(query)
                    val authCode = queryParams["code"]

                    if (!authCode.isNullOrEmpty()) {
                        thread {
                            try {
                                handleAuthentication(authCode)
                            } catch (e: Exception) {
                                e.printStackTrace()
                            }
                        }

                        val response = "Authentication in progress... Please check console for results."
                        exchange.sendResponseHeaders(200, response.toByteArray().size.toLong())
                        exchange.responseBody.use { os: OutputStream ->
                            os.write(response.toByteArray())
                        }
                    } else {
                        val response = "Authorization code not received"
                        exchange.sendResponseHeaders(400, response.toByteArray().size.toLong())
                        exchange.responseBody.use { os: OutputStream ->
                            os.write(response.toByteArray())
                        }
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                    val response = "Internal server error: ${e.message}"
                    exchange.sendResponseHeaders(500, response.toByteArray().size.toLong())
                    exchange.responseBody.use { os: OutputStream ->
                        os.write(response.toByteArray())
                    }
                }
            }

            // Handle data endpoint
            server.createContext("/data/") { exchange ->
                try {
                    val path = exchange.requestURI.path
                    val playerUUID = path.substring("/data/".length).replace(".json", "")

                    val authData = authDataMap[playerUUID]
                    if (authData != null) {
                        val jsonResponse = json.encodeToString(authData)
                        exchange.responseHeaders.set("Content-Type", "application/json")
                        exchange.sendResponseHeaders(200, jsonResponse.toByteArray().size.toLong())
                        exchange.responseBody.use { os: OutputStream ->
                            os.write(jsonResponse.toByteArray())
                        }
                    } else {
                        val response = "Data not found or expired"
                        exchange.sendResponseHeaders(404, response.toByteArray().size.toLong())
                        exchange.responseBody.use { os: OutputStream ->
                            os.write(response.toByteArray())
                        }
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }

            server.executor = Executors.newCachedThreadPool()
            server.start()

            println("Server started on port: $PORT")
            println("Please visit the following URL for authorization:")
            println(generateAuthorizeUrl())
            println("Waiting for authorization...")

            // Wait for key press to exit
            println("\nPress Enter to exit at any time...")
            readLine()

            server.stop(0)
            println("Server stopped.")
        }

        private fun handleAuthentication(authCode: String) {
            try {
                println("[1/6] Exchanging authorization code for Microsoft token...")
                val tokenData = exchangeCodeForToken(authCode)
                val accessToken = tokenData["access_token"]!!.jsonPrimitive.content

                println("[2/6] Xbox Live authentication...")
                val xblData = authenticateXboxLive(accessToken)
                val xblToken = xblData["Token"]!!.jsonPrimitive.content
                val userHash = xblData["DisplayClaims"]!!.jsonObject["xui"]!!
                    .jsonArray[0].jsonObject["uhs"]!!.jsonPrimitive.content

                println("[3/6] XSTS authentication...")
                val xstsData = authenticateXSTS(xblToken)
                val xstsToken = xstsData["Token"]!!.jsonPrimitive.content

                println("[4/6] Getting Minecraft access token...")
                val mcTokenData = loginWithXbox(userHash, xstsToken)
                val mcAccessToken = mcTokenData["access_token"]!!.jsonPrimitive.content

                println("[5/6] Checking game ownership...")
                val entitlements = checkGameOwnership(mcAccessToken)
                if (!entitlements.containsKey("items") ||
                    entitlements["items"]!!.jsonArray.isEmpty()) {
                    throw RuntimeException("This account does not own Minecraft")
                }

                println("[6/6] Getting Minecraft profile...")
                val profile = getMinecraftProfile(mcAccessToken)
                val playerUUID = profile["id"]!!.jsonPrimitive.content

                // Store data
                val authData = AuthData(
                    tokens = AuthData.Tokens(
                        microsoft_access_token = accessToken,
                        microsoft_refresh_token = tokenData["refresh_token"]!!.jsonPrimitive.content,
                        xbl_token = xblToken,
                        xsts_token = xstsToken,
                        minecraft_access_token = mcAccessToken,
                        expires_in = mcTokenData["expires_in"]!!.jsonPrimitive.int
                    ),
                    profile = profile,
                    pkce = AuthData.PKCE(
                        code_verifier = CODE_VERIFIER,
                        code_challenge = CODE_CHALLENGE
                    )
                )

                authDataMap[playerUUID] = authData

                println("\nDone.")
                println("\nData access URL:")
                println("http://localhost:$PORT/data/$playerUUID.json")
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

        private fun generateRandomString(length: Int): String {
            val random = SecureRandom()
            val bytes = ByteArray(ceil(length / 2.0).toInt())
            random.nextBytes(bytes)
            return bytesToHex(bytes).substring(0, length)
        }

        private fun bytesToHex(bytes: ByteArray): String {
            return bytes.joinToString("") { "%02x".format(it) }
        }

        private fun generateCodeChallenge(codeVerifier: String): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(codeVerifier.toByteArray(StandardCharsets.UTF_8))
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
        }

        private fun generateAuthorizeUrl(): String {
            val params = mapOf(
                "client_id" to CLIENT_ID,
                "response_type" to "code",
                "redirect_uri" to REDIRECT_URI,
                "scope" to SCOPE,
                "code_challenge" to CODE_CHALLENGE,
                "code_challenge_method" to "S256",
                "prompt" to "select_account"
            )

            return "$AUTHORIZE_URL?${params.entries.joinToString("&") { "${it.key}=${it.value.urlEncode()}" }}"
        }

        private fun String.urlEncode(): String {
            return URLEncoder.encode(this, "UTF-8")
        }

        private fun exchangeCodeForToken(authCode: String): JsonObject {
            val params = mapOf(
                "client_id" to CLIENT_ID,
                "code" to authCode,
                "redirect_uri" to REDIRECT_URI,
                "grant_type" to "authorization_code",
                "code_verifier" to CODE_VERIFIER
            )

            val body = buildFormData(params)

            val request = HttpRequest.newBuilder()
                .uri(URI.create(TOKEN_URL))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()

            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() == 200) {
                return json.parseToJsonElement(response.body()).jsonObject
            } else {
                throw RuntimeException("Token exchange failed: ${response.body()}")
            }
        }

        private fun authenticateXboxLive(accessToken: String): JsonObject {
            val rpsTickets = listOf("d=$accessToken", accessToken)

            for (rpsTicket in rpsTickets) {
                val data = buildJsonObject {
                    put("Properties", buildJsonObject {
                        put("AuthMethod", "RPS")
                        put("SiteName", "user.auth.xboxlive.com")
                        put("RpsTicket", rpsTicket)
                    })
                    put("RelyingParty", "http://auth.xboxlive.com")
                    put("TokenType", "JWT")
                }

                val request = HttpRequest.newBuilder()
                    .uri(URI.create(XBL_AUTH_URL))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
                    .build()

                val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

                if (response.statusCode() == 200) {
                    return json.parseToJsonElement(response.body()).jsonObject
                }
            }

            throw RuntimeException("Xbox Live authentication failed")
        }

        private fun authenticateXSTS(xblToken: String): JsonObject {
            val data = buildJsonObject {
                put("Properties", buildJsonObject {
                    put("SandboxId", "RETAIL")
                    put("UserTokens", buildJsonArray {
                        add(xblToken)
                    })
                })
                put("RelyingParty", "rp://api.minecraftservices.com/")
                put("TokenType", "JWT")
            }

            val request = HttpRequest.newBuilder()
                .uri(URI.create(XSTS_AUTH_URL))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
                .build()

            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() == 200) {
                return json.parseToJsonElement(response.body()).jsonObject
            } else {
                throw RuntimeException("XSTS authentication failed: ${response.body()}")
            }
        }

        private fun loginWithXbox(userHash: String, xstsToken: String): JsonObject {
            val data = buildJsonObject {
                put("identityToken", "XBL3.0 x=$userHash;$xstsToken")
            }

            val request = HttpRequest.newBuilder()
                .uri(URI.create(MC_LOGIN_URL))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(data.toString()))
                .build()

            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() == 200) {
                return json.parseToJsonElement(response.body()).jsonObject
            } else {
                throw RuntimeException("Minecraft login failed: ${response.body()}")
            }
        }

        private fun checkGameOwnership(mcAccessToken: String): JsonObject {
            val request = HttpRequest.newBuilder()
                .uri(URI.create(MC_ENTITLEMENTS_URL))
                .header("Authorization", "Bearer $mcAccessToken")
                .header("Accept", "application/json")
                .GET()
                .build()

            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() == 200) {
                return json.parseToJsonElement(response.body()).jsonObject
            } else {
                throw RuntimeException("Game ownership check failed: ${response.body()}")
            }
        }

        private fun getMinecraftProfile(mcAccessToken: String): JsonObject {
            val request = HttpRequest.newBuilder()
                .uri(URI.create(PROFILE_URL))
                .header("Authorization", "Bearer $mcAccessToken")
                .header("Accept", "application/json")
                .GET()
                .build()

            val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())

            if (response.statusCode() == 200) {
                return json.parseToJsonElement(response.body()).jsonObject
            } else {
                throw RuntimeException("Profile fetch failed: ${response.body()}")
            }
        }

        private fun buildFormData(params: Map<String, String>): String {
            return params.entries.joinToString("&") { "${it.key}=${it.value.urlEncode()}" }
        }

        private fun parseQuery(query: String?): Map<String, String> {
            val result = mutableMapOf<String, String>()
            if (query.isNullOrEmpty()) {
                return result
            }

            query.split("&").forEach { param ->
                val pair = param.split("=")
                if (pair.size == 2) {
                    result[pair[0]] = URLDecoder.decode(pair[1], "UTF-8")
                }
            }
            return result
        }
    }
}