// main.go
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	CLIENT_ID     = "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
	REDIRECT_URI  = "http://localhost:3000/proxy/"
	SCOPE         = "XboxLive.signin offline_access"
	AUTHORIZE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
	TOKEN_URL     = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
	XBL_AUTH_URL  = "https://user.auth.xboxlive.com/user/authenticate"
	XSTS_AUTH_URL = "https://xsts.auth.xboxlive.com/xsts/authorize"
	MC_LOGIN_URL  = "https://api.minecraftservices.com/authentication/login_with_xbox"
	MC_STORE_URL  = "https://api.minecraftservices.com/entitlements/mcstore"
	PROFILE_URL   = "https://api.minecraftservices.com/minecraft/profile"
	PORT          = 3000
)

var (
	codeVerifier  = "W6i3P9qL8zX2rV5sT1uY4aB7cD0eF3gH6jK9mN2pQ5s"
	codeChallenge = generateCodeChallenge(codeVerifier)
	authDataMap   = sync.Map{}
	httpClient    = &http.Client{Timeout: 30 * time.Second}
)

type AuthData struct {
	Tokens  Tokens   `json:"tokens"`
	Profile Profile  `json:"profile"`
	PKCE    PKCEData `json:"pkce"`
}

type Tokens struct {
	MicrosoftAccessToken  string `json:"microsoft_access_token"`
	MicrosoftRefreshToken string `json:"microsoft_refresh_token"`
	XBLToken              string `json:"xbl_token"`
	XSTSToken             string `json:"xsts_token"`
	MinecraftAccessToken  string `json:"minecraft_access_token"`
	ExpiresIn             int    `json:"expires_in"`
}

type PKCEData struct {
	CodeVerifier  string `json:"code_verifier"`
	CodeChallenge string `json:"code_challenge"`
}

type Profile map[string]interface{}

func generateRandomString(length int) string {
	bts := make([]byte, length)
	rand.Read(bts)
	return hex.EncodeToString(bts)[:length]
}

func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}

func generateAuthorizeUrl() string {
	params := url.Values{}
	params.Add("client_id", CLIENT_ID)
	params.Add("response_type", "code")
	params.Add("redirect_uri", REDIRECT_URI)
	params.Add("scope", SCOPE)
	params.Add("code_challenge", codeChallenge)
	params.Add("code_challenge_method", "S256")
	params.Add("prompt", "select_account")

	return AUTHORIZE_URL + "?" + params.Encode()
}

func startServer() {
	http.HandleFunc("/proxy/", handleOAuthCallback)
	http.HandleFunc("/data/", handleDataRequest)

	fmt.Printf("Server started on port: %d\n", PORT)
	fmt.Println("Please visit the following URL for authorization:")
	fmt.Println(generateAuthorizeUrl())
	fmt.Println("Waiting for authorization...")

	go func() {
		if err := http.ListenAndServe(fmt.Sprintf(":%d", PORT), nil); err != nil {
			panic(err)
		}
	}()

	fmt.Println("\nPress Enter to exit at any time...")
	fmt.Scanln()
}

func handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	authCode := query.Get("code")

	if authCode == "" {
		http.Error(w, "Authorization code not received", http.StatusBadRequest)
		return
	}

	go handleAuthentication(authCode)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Authentication in progress... Please check console for results."))
}

func handleDataRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	playerUUID := strings.TrimPrefix(path, "/data/")
	playerUUID = strings.TrimSuffix(playerUUID, ".json")

	if data, ok := authDataMap.Load(playerUUID); ok {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
	} else {
		http.Error(w, "Data not found or expired", http.StatusNotFound)
	}
}

func handleAuthentication(authCode string) {
	fmt.Println("[1/6] Exchanging authorization code for Microsoft token...")
	tokenData, err := exchangeCodeForToken(authCode)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	accessToken := tokenData["access_token"].(string)

	fmt.Println("[2/6] Xbox Live authentication...")
	xblData, err := authenticateXboxLive(accessToken)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	xblToken := xblData["Token"].(string)
	userHash := xblData["DisplayClaims"].(map[string]interface{})["xui"].([]interface{})[0].(map[string]interface{})["uhs"].(string)

	fmt.Println("[3/6] XSTS authentication...")
	xstsData, err := authenticateXSTS(xblToken)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	xstsToken := xstsData["Token"].(string)

	fmt.Println("[4/6] Getting Minecraft access token...")
	mcTokenData, err := loginWithXbox(userHash, xstsToken)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	mcAccessToken := mcTokenData["access_token"].(string)

	fmt.Println("[5/6] Checking game ownership...")
	entitlements, err := checkGameOwnership(mcAccessToken)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	items, _ := entitlements["items"].([]interface{})
	if items == nil || len(items) == 0 {
		fmt.Println("Error: This account does not own Minecraft")
		return
	}

	fmt.Println("[6/6] Getting Minecraft profile...")
	profile, err := getMinecraftProfile(mcAccessToken)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	playerUUID := profile["id"].(string)

	authData := AuthData{
		Tokens: Tokens{
			MicrosoftAccessToken:  accessToken,
			MicrosoftRefreshToken: tokenData["refresh_token"].(string),
			XBLToken:              xblToken,
			XSTSToken:             xstsToken,
			MinecraftAccessToken:  mcAccessToken,
			ExpiresIn:             int(tokenData["expires_in"].(float64)),
		},
		Profile: profile,
		PKCE: PKCEData{
			CodeVerifier:  codeVerifier,
			CodeChallenge: codeChallenge,
		},
	}

	authDataMap.Store(playerUUID, authData)

	fmt.Println("\nDone.")
	fmt.Println("\nData access URL:")
	fmt.Printf("http://localhost:%d/data/%s.json\n", PORT, playerUUID)
}

func exchangeCodeForToken(authCode string) (map[string]interface{}, error) {
	data := url.Values{}
	data.Set("client_id", CLIENT_ID)
	data.Set("code", authCode)
	data.Set("redirect_uri", REDIRECT_URI)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", codeVerifier)

	req, _ := http.NewRequest("POST", TOKEN_URL, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed: %s", string(body))
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func authenticateXboxLive(accessToken string) (map[string]interface{}, error) {
	rpsTickets := []string{"d=" + accessToken, accessToken}

	for _, rpsTicket := range rpsTickets {
		data := map[string]interface{}{
			"Properties": map[string]interface{}{
				"AuthMethod": "RPS",
				"SiteName":   "user.auth.xboxlive.com",
				"RpsTicket":  rpsTicket,
			},
			"RelyingParty": "http://auth.xboxlive.com",
			"TokenType":    "JWT",
		}

		jsonData, _ := json.Marshal(data)
		req, _ := http.NewRequest("POST", XBL_AUTH_URL, bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			var result map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&result)
			return result, nil
		}
	}

	return nil, fmt.Errorf("Xbox Live authentication failed")
}

func authenticateXSTS(xblToken string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"Properties": map[string]interface{}{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{xblToken},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	}

	jsonData, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", XSTS_AUTH_URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("XSTS authentication failed: %s", string(body))
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func loginWithXbox(userHash, xstsToken string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"identityToken": fmt.Sprintf("XBL3.0 x=%s;%s", userHash, xstsToken),
	}

	jsonData, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", MC_LOGIN_URL, bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Minecraft login failed: %s", string(body))
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func checkGameOwnership(mcAccessToken string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", MC_STORE_URL, nil)
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("game ownership check failed: %s", string(body))
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func getMinecraftProfile(mcAccessToken string) (map[string]interface{}, error) {
	req, _ := http.NewRequest("GET", PROFILE_URL, nil)
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("profile fetch failed: %s", string(body))
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func main() {
	startServer()
}
