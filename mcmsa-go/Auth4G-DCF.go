package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	CLIENT_ID         = "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
	SCOPE             = "XboxLive.signin offline_access openid profile email"
	DEVICE_CODE_URL   = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
	TOKEN_URL         = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
	XBL_AUTH_URL      = "https://user.auth.xboxlive.com/user/authenticate"
	XSTS_AUTH_URL     = "https://xsts.auth.xboxlive.com/xsts/authorize"
	MC_LOGIN_URL      = "https://api.minecraftservices.com/authentication/login_with_xbox"
	MC_STORE_URL      = "https://api.minecraftservices.com/entitlements/mcstore"
	PROFILE_URL       = "https://api.minecraftservices.com/minecraft/profile"
	POLL_INTERVAL     = 5 * time.Second
	MAX_POLL_ATTEMPTS = 180
)

var (
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Message         string `json:"message"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
}

type XboxAuthResponse struct {
	Token         string                 `json:"Token"`
	DisplayClaims map[string]interface{} `json:"DisplayClaims"`
}

type XSTSResponse struct {
	Token string `json:"Token"`
}

type MinecraftTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type MinecraftProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type EntitlementsResponse struct {
	Items []interface{} `json:"items"`
}

type AuthResult struct {
	Timestamp string           `json:"timestamp"`
	Player    PlayerInfo       `json:"player"`
	Tokens    TokenInfo        `json:"tokens"`
	Profile   MinecraftProfile `json:"profile"`
}

type PlayerInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type TokenInfo struct {
	Microsoft MicrosoftTokens `json:"microsoft"`
	Xbox      XboxTokens      `json:"xbox"`
	Minecraft MinecraftTokens `json:"minecraft"`
}

type MicrosoftTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

type XboxTokens struct {
	XBLToken  string `json:"xbl_token"`
	XSTSToken string `json:"xsts_token"`
}

type MinecraftTokens struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := startDeviceAuth(ctx); err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
}

func startDeviceAuth(ctx context.Context) error {
	// 1. 获取设备码
	fmt.Println("[1/7] Requesting device code...")
	deviceCodeResp, err := requestDeviceCode()
	if err != nil {
		return fmt.Errorf("failed to get device code: %w", err)
	}

	fmt.Printf("\nPlease visit: %s\n", deviceCodeResp.VerificationURI)
	fmt.Printf("Enter this code: %s\n", deviceCodeResp.UserCode)
	fmt.Println("\nWaiting for authentication...")

	// 2. 轮询获取令牌
	fmt.Println("[2/7] Polling for token...")
	tokenResp, err := pollForToken(ctx, deviceCodeResp.DeviceCode, deviceCodeResp.Interval)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}

	fmt.Println("[3/7] Microsoft token obtained")

	// 3. Xbox Live认证
	fmt.Println("[4/7] Xbox Live authentication...")
	xblData, err := authenticateXboxLive(tokenResp.AccessToken)
	if err != nil {
		return fmt.Errorf("Xbox Live authentication failed: %w", err)
	}

	xblToken := xblData.Token
	userHash, err := extractUserHash(xblData.DisplayClaims)
	if err != nil {
		return fmt.Errorf("failed to extract user hash: %w", err)
	}

	// 4. XSTS认证
	fmt.Println("[5/7] XSTS authentication...")
	xstsData, err := authenticateXSTS(xblToken)
	if err != nil {
		return fmt.Errorf("XSTS authentication failed: %w", err)
	}

	xstsToken := xstsData.Token

	// 5. Minecraft登录
	fmt.Println("[6/7] Minecraft login...")
	mcTokenData, err := loginToMinecraft(userHash, xstsToken)
	if err != nil {
		return fmt.Errorf("Minecraft login failed: %w", err)
	}

	mcAccessToken := mcTokenData.AccessToken

	// 6. 检查游戏所有权（可选）
	fmt.Println("[6.5/7] Checking game ownership...")
	ownsGame, err := checkGameOwnership(mcAccessToken)
	if err != nil {
		fmt.Printf("Warning: Failed to check game ownership: %v\n", err)
	} else if !ownsGame {
		return fmt.Errorf("this account does not own Minecraft")
	}

	// 7. 获取Minecraft档案
	fmt.Println("[7/7] Getting Minecraft profile...")
	profile, err := getMinecraftProfile(mcAccessToken)
	if err != nil {
		return fmt.Errorf("failed to get Minecraft profile: %w", err)
	}

	// 构建认证结果
	authResult := buildAuthResult(profile, tokenResp, xblToken, xstsToken, mcTokenData)

	// 输出结果
	printAuthResult(authResult)

	return nil
}

func requestDeviceCode() (*DeviceCodeResponse, error) {
	data := url.Values{}
	data.Set("client_id", CLIENT_ID)
	data.Set("scope", SCOPE)

	req, err := http.NewRequest("POST", DEVICE_CODE_URL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("device code request failed: %s", string(body))
	}

	var result DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func pollForToken(ctx context.Context, deviceCode string, interval int) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("client_id", CLIENT_ID)
	data.Set("device_code", deviceCode)

	pollInterval := time.Duration(interval) * time.Second
	if pollInterval == 0 {
		pollInterval = POLL_INTERVAL
	}

	for attempt := 0; attempt < MAX_POLL_ATTEMPTS; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
			req, err := http.NewRequest("POST", TOKEN_URL, strings.NewReader(data.Encode()))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := httpClient.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				var result TokenResponse
				if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
					return nil, err
				}
				if result.AccessToken != "" {
					fmt.Print(".")
					return &result, nil
				}
			} else if resp.StatusCode == http.StatusBadRequest {
				body, _ := ioutil.ReadAll(resp.Body)
				var errorResp map[string]interface{}
				if json.Unmarshal(body, &errorResp) == nil {
				}
			}
		}
	}
	return nil, fmt.Errorf("authentication timeout")
}

func authenticateXboxLive(accessToken string) (*XboxAuthResponse, error) {
	// 尝试两种格式的RPS票据
	rpsTickets := []string{"d=" + accessToken, accessToken}

	for _, rpsTicket := range rpsTickets {
		payload := map[string]interface{}{
			"Properties": map[string]interface{}{
				"AuthMethod": "RPS",
				"SiteName":   "user.auth.xboxlive.com",
				"RpsTicket":  rpsTicket,
			},
			"RelyingParty": "http://auth.xboxlive.com",
			"TokenType":    "JWT",
		}

		jsonData, _ := json.Marshal(payload)
		req, err := http.NewRequest("POST", XBL_AUTH_URL, bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var result XboxAuthResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				continue
			}
			return &result, nil
		}
	}

	return nil, fmt.Errorf("all authentication attempts failed")
}

func extractUserHash(displayClaims map[string]interface{}) (string, error) {
	xuiInterface, ok := displayClaims["xui"]
	if !ok {
		return "", fmt.Errorf("no xui in display claims")
	}

	xuiArray, ok := xuiInterface.([]interface{})
	if !ok || len(xuiArray) == 0 {
		return "", fmt.Errorf("invalid xui array")
	}

	firstXui, ok := xuiArray[0].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("invalid xui format")
	}

	userHash, ok := firstXui["uhs"].(string)
	if !ok {
		return "", fmt.Errorf("no uhs in xui")
	}

	return userHash, nil
}

func authenticateXSTS(xblToken string) (*XSTSResponse, error) {
	payload := map[string]interface{}{
		"Properties": map[string]interface{}{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{xblToken},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	}

	jsonData, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", XSTS_AUTH_URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("XSTS authentication failed: %s", string(body))
	}

	var result XSTSResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func loginToMinecraft(userHash, xstsToken string) (*MinecraftTokenResponse, error) {
	payload := map[string]interface{}{
		"identityToken": fmt.Sprintf("XBL3.0 x=%s;%s", userHash, xstsToken),
	}

	jsonData, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", MC_LOGIN_URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("Minecraft login failed: %s", string(body))
	}

	var result MinecraftTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func checkGameOwnership(mcAccessToken string) (bool, error) {
	req, err := http.NewRequest("GET", MC_STORE_URL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var result EntitlementsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	return len(result.Items) > 0, nil
}

func getMinecraftProfile(mcAccessToken string) (*MinecraftProfile, error) {
	req, err := http.NewRequest("GET", PROFILE_URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("profile fetch failed: %s", string(body))
	}

	var result MinecraftProfile
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func buildAuthResult(profile *MinecraftProfile, tokenResp *TokenResponse,
	xblToken, xstsToken string, mcTokenData *MinecraftTokenResponse) *AuthResult {

	return &AuthResult{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Player: PlayerInfo{
			ID:   profile.ID,
			Name: profile.Name,
		},
		Tokens: TokenInfo{
			Microsoft: MicrosoftTokens{
				AccessToken:  tokenResp.AccessToken,
				RefreshToken: tokenResp.RefreshToken,
				ExpiresIn:    tokenResp.ExpiresIn,
				Scope:        tokenResp.Scope,
			},
			Xbox: XboxTokens{
				XBLToken:  xblToken,
				XSTSToken: xstsToken,
			},
			Minecraft: MinecraftTokens{
				AccessToken: mcTokenData.AccessToken,
				ExpiresIn:   mcTokenData.ExpiresIn,
			},
		},
		Profile: *profile,
	}
}

func printAuthResult(result *AuthResult) {
	fmt.Println("\n--- AUTHENTICATION DATA ---")

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("Error formatting JSON: %v\n", err)
		return
	}
	fmt.Println(string(jsonData))
}
