package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	CLIENT_ID = "4a07b708-b86d-4365-a55f-f4f23ecb85ab"
	SCOPE     = "XboxLive.signin offline_access openid profile email"

	DEVICE_CODE_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode"
	TOKEN_URL       = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
	XBL_AUTH_URL    = "https://user.auth.xboxlive.com/user/authenticate"
	XSTS_AUTH_URL   = "https://xsts.auth.xboxlive.com/xsts/authorize"
	MC_LOGIN_URL    = "https://api.minecraftservices.com/authentication/login_with_xbox"
	PROFILE_URL     = "https://api.minecraftservices.com/minecraft/profile"
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

type XboxAuthRequest struct {
	Properties   XboxAuthProperties `json:"Properties"`
	RelyingParty string             `json:"RelyingParty"`
	TokenType    string             `json:"TokenType"`
}

type XboxAuthProperties struct {
	AuthMethod string `json:"AuthMethod"`
	SiteName   string `json:"SiteName"`
	RpsTicket  string `json:"RpsTicket"`
}

type XboxAuthResponse struct {
	Token         string               `json:"Token"`
	DisplayClaims XboxDisplayClaims    `json:"DisplayClaims"`
}

type XboxDisplayClaims struct {
	Xui []XboxXui `json:"xui"`
}

type XboxXui struct {
	Uhs string `json:"uhs"`
}

type XstsAuthRequest struct {
	Properties   XstsAuthProperties `json:"Properties"`
	RelyingParty string             `json:"RelyingParty"`
	TokenType    string             `json:"TokenType"`
}

type XstsAuthProperties struct {
	SandboxId  string   `json:"SandboxId"`
	UserTokens []string `json:"UserTokens"`
}

type XstsAuthResponse struct {
	Token string `json:"Token"`
}

type MinecraftLoginRequest struct {
	IdentityToken string `json:"identityToken"`
}

type MinecraftLoginResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type Skin struct {
	Id         string `json:"id"`
	State      string `json:"state"`
	Url        string `json:"url"`
	TextureKey string `json:"textureKey"`
	Variant    string `json:"variant"`
}

type Cape struct {
	Id    string `json:"id"`
	State string `json:"state"`
	Url   string `json:"url"`
	Alias string `json:"alias"`
}

type MinecraftProfile struct {
	Id             string            `json:"id"`
	Name           string            `json:"name"`
	Skins          []Skin            `json:"skins"`
	Capes          []Cape            `json:"capes"`
	ProfileActions map[string]string `json:"profileActions"`
}

type AuthResult struct {
	Tokens  AuthTokens     `json:"tokens"`
	Profile MinecraftProfile `json:"profile"`
}

type AuthTokens struct {
	MicrosoftAccessToken  string `json:"microsoft_access_token"`
	MicrosoftRefreshToken string `json:"microsoft_refresh_token"`
	XblToken              string `json:"xbl_token"`
	XstsToken             string `json:"xsts_token"`
	MinecraftAccessToken  string `json:"minecraft_access_token"`
	ExpiresIn             int    `json:"expires_in"`
}

type MinecraftAuthenticator struct {
	client *http.Client
}

func NewMinecraftAuthenticator() *MinecraftAuthenticator {
	return &MinecraftAuthenticator{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (m *MinecraftAuthenticator) Authenticate() (*AuthResult, error) {
	fmt.Println("Minecraft Authentication - Device Code Flow\n")

	fmt.Println("[1/6] Requesting device code...")
	deviceCodeResp, err := m.requestDeviceCode()
	if err != nil {
		return nil, err
	}

	fmt.Printf("\nVisit this URL: %s\n", deviceCodeResp.VerificationURI)
	fmt.Printf("Enter this code: %s\n", deviceCodeResp.UserCode)
	fmt.Println("Waiting for authentication...")

	tokenResp, err := m.pollForToken(deviceCodeResp.DeviceCode, deviceCodeResp.Interval)
	if err != nil {
		return nil, err
	}
	fmt.Println("\n[2/6] Polling for token...")

	xblData, err := m.authenticateWithXboxLive(tokenResp.AccessToken)
	if err != nil {
		return nil, err
	}
	xblToken := xblData.Token
	userHash := xblData.DisplayClaims.Xui[0].Uhs
	fmt.Println("[3/6] Xbox Live authentication...")

	xstsData, err := m.authenticateWithXSTS(xblToken)
	if err != nil {
		return nil, err
	}
	xstsToken := xstsData.Token
	fmt.Println("[4/6] XSTS authentication...")

	mcTokenData, err := m.loginToMinecraft(userHash, xstsToken)
	if err != nil {
		return nil, err
	}
	mcAccessToken := mcTokenData.AccessToken
	fmt.Println("[5/6] Minecraft login...")

	profile, err := m.getMinecraftProfile(mcAccessToken)
	if err != nil {
		return nil, err
	}
	fmt.Println("[6/6] Getting profile...")

	return &AuthResult{
		Tokens: AuthTokens{
			MicrosoftAccessToken:  tokenResp.AccessToken,
			MicrosoftRefreshToken: tokenResp.RefreshToken,
			XblToken:              xblToken,
			XstsToken:             xstsToken,
			MinecraftAccessToken:  mcAccessToken,
			ExpiresIn:             mcTokenData.ExpiresIn,
		},
		Profile: *profile,
	}, nil
}

func (m *MinecraftAuthenticator) requestDeviceCode() (*DeviceCodeResponse, error) {
	formData := url.Values{}
	formData.Set("client_id", CLIENT_ID)
	formData.Set("scope", SCOPE)

	req, err := http.NewRequest("POST", DEVICE_CODE_URL, strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (m *MinecraftAuthenticator) pollForToken(deviceCode string, interval int) (*TokenResponse, error) {
	pollInterval := interval
	if pollInterval < 5 {
		pollInterval = 5
	}
	maxAttempts := 180

	for attempt := 0; attempt < maxAttempts; attempt++ {
		formData := url.Values{}
		formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		formData.Set("client_id", CLIENT_ID)
		formData.Set("device_code", deviceCode)

		req, err := http.NewRequest("POST", TOKEN_URL, strings.NewReader(formData.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := m.client.Do(req)
		if err != nil {
			if attempt == maxAttempts-1 {
				return nil, fmt.Errorf("authentication timeout - please try again: %w", err)
			}
			time.Sleep(time.Duration(pollInterval) * time.Second)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var result TokenResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				resp.Body.Close()
				return nil, err
			}
			resp.Body.Close()
			return &result, nil
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var errorObj map[string]interface{}
		if err := json.Unmarshal(body, &errorObj); err == nil {
			if errorValue, ok := errorObj["error"].(string); ok && errorValue == "authorization_pending" {
				time.Sleep(time.Duration(pollInterval) * time.Second)
				continue
			}
		}

		if attempt == maxAttempts-1 {
			return nil, fmt.Errorf("authentication timeout - please try again")
		}
		time.Sleep(time.Duration(pollInterval) * time.Second)
	}

	return nil, fmt.Errorf("authentication timeout - please try again")
}

func (m *MinecraftAuthenticator) authenticateWithXboxLive(accessToken string) (*XboxAuthResponse, error) {
	attempts := []string{"d=" + accessToken, accessToken}

	for _, rpsTicket := range attempts {
		requestBody := XboxAuthRequest{
			Properties: XboxAuthProperties{
				AuthMethod: "RPS",
				SiteName:   "user.auth.xboxlive.com",
				RpsTicket:  rpsTicket,
			},
			RelyingParty: "http://auth.xboxlive.com",
			TokenType:    "JWT",
		}

		jsonData, err := json.Marshal(requestBody)
		if err != nil {
			continue
		}

		req, err := http.NewRequest("POST", XBL_AUTH_URL, bytes.NewBuffer(jsonData))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := m.client.Do(req)
		if err != nil {
			continue
		}

		if resp.StatusCode == http.StatusOK {
			var result XboxAuthResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				resp.Body.Close()
				continue
			}
			resp.Body.Close()
			return &result, nil
		}
		resp.Body.Close()
	}

	return nil, fmt.Errorf("Xbox Live authentication failed with both RPS ticket formats")
}

func (m *MinecraftAuthenticator) authenticateWithXSTS(xblToken string) (*XstsAuthResponse, error) {
	requestBody := XstsAuthRequest{
		Properties: XstsAuthProperties{
			SandboxId:  "RETAIL",
			UserTokens: []string{xblToken},
		},
		RelyingParty: "rp://api.minecraftservices.com/",
		TokenType:    "JWT",
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", XSTS_AUTH_URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result XstsAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (m *MinecraftAuthenticator) loginToMinecraft(userHash, xstsToken string) (*MinecraftLoginResponse, error) {
	requestBody := MinecraftLoginRequest{
		IdentityToken: fmt.Sprintf("XBL3.0 x=%s;%s", userHash, xstsToken),
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", MC_LOGIN_URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result MinecraftLoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (m *MinecraftAuthenticator) getMinecraftProfile(mcAccessToken string) (*MinecraftProfile, error) {
	req, err := http.NewRequest("GET", PROFILE_URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+mcAccessToken)

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result MinecraftProfile
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func main() {
	authenticator := NewMinecraftAuthenticator()
	result, err := authenticator.Authenticate()
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		return
	}

	fmt.Println("\nDone!")
	fmt.Println("You can use the following sample code to retrieve any field from the returned JSON:\n")
	fmt.Println("authenticator := NewMinecraftAuthenticator()")
	fmt.Println("result, err := authenticator.Authenticate()")
	fmt.Println("accessToken := result.Tokens.MinecraftAccessToken")
	fmt.Println("fmt.Println(accessToken)\n")
	fmt.Println("Below is the JSON returned from your recent login operation:\n")

	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("Error formatting JSON: %v\n", err)
		return
	}
	fmt.Println(string(jsonData))
}