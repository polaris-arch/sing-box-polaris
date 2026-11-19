package ccm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service/filemanager"
)

const (
	oauth2ClientID          = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	oauth2TokenURL          = "https://console.anthropic.com/v1/oauth/token"
	maxOAuthResponseBytes   = 1 << 20
	claudeAPIBaseURL        = "https://api.anthropic.com"
	tokenRefreshBufferMs    = 60000
	anthropicBetaOAuthValue = "oauth-2025-04-20"
)

func getRealUser() (*user.User, error) {
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		sudoUserInfo, err := user.Lookup(sudoUser)
		if err == nil {
			return sudoUserInfo, nil
		}
	}
	return user.Current()
}

func getDefaultCredentialsPath() (string, error) {
	if configDir := os.Getenv("CLAUDE_CONFIG_DIR"); configDir != "" {
		return filepath.Join(configDir, ".credentials.json"), nil
	}
	userInfo, err := getRealUser()
	if err != nil {
		return "", err
	}
	return filepath.Join(userInfo.HomeDir, ".claude", ".credentials.json"), nil
}

func readCredentialsFromFile(ctx context.Context, path string) (*oauthCredentials, error) {
	data, err := filemanager.ReadFile(ctx, path)
	if err != nil {
		return nil, err
	}
	var credentialsContainer struct {
		ClaudeAIAuth *oauthCredentials `json:"claudeAiOauth,omitempty"`
	}
	err = json.Unmarshal(data, &credentialsContainer)
	if err != nil {
		return nil, err
	}
	if credentialsContainer.ClaudeAIAuth == nil {
		return nil, E.New("claudeAiOauth field not found in credentials")
	}
	return credentialsContainer.ClaudeAIAuth, nil
}

func writeCredentialsToFile(ctx context.Context, oauthCredentials *oauthCredentials, path string) error {
	data, err := json.MarshalIndent(map[string]any{
		"claudeAiOauth": oauthCredentials,
	}, "", "  ")
	if err != nil {
		return err
	}
	return filemanager.WriteFile(ctx, path, data, 0o600)
}

type oauthCredentials struct {
	AccessToken      string   `json:"accessToken"`
	RefreshToken     string   `json:"refreshToken"`
	ExpiresAt        int64    `json:"expiresAt"`
	Scopes           []string `json:"scopes,omitempty"`
	SubscriptionType string   `json:"subscriptionType,omitempty"`
	IsMax            bool     `json:"isMax,omitempty"`
}

func (c *oauthCredentials) needsRefresh() bool {
	if c.ExpiresAt == 0 {
		return false
	}
	return time.Now().UnixMilli() >= c.ExpiresAt-tokenRefreshBufferMs
}

func refreshToken(ctx context.Context, httpClient *http.Client, credentials *oauthCredentials) (*oauthCredentials, error) {
	if credentials.RefreshToken == "" {
		return nil, E.New("refresh token is empty")
	}

	requestBody, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": credentials.RefreshToken,
		"client_id":     oauth2ClientID,
	})
	if err != nil {
		return nil, E.Cause(err, "marshal request")
	}

	ctx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "POST", oauth2TokenURL, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Admit the whole body before accepting any tokens, even when a valid
	// JSON object comes before an oversized or interrupted remainder.
	body, err := io.ReadAll(http.MaxBytesReader(nil, response.Body, maxOAuthResponseBytes))
	if response.StatusCode != http.StatusOK {
		if err != nil {
			return nil, E.Cause(err, "refresh failed: ", response.Status)
		}
		return nil, E.New("refresh failed: ", response.Status, " ", string(body))
	}
	if err != nil {
		return nil, E.Cause(err, "read response")
	}

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return nil, E.Cause(err, "decode response")
	}

	newCredentials := *credentials
	newCredentials.AccessToken = tokenResponse.AccessToken
	if tokenResponse.RefreshToken != "" {
		newCredentials.RefreshToken = tokenResponse.RefreshToken
	}
	newCredentials.ExpiresAt = time.Now().UnixMilli() + int64(tokenResponse.ExpiresIn)*1000

	return &newCredentials, nil
}
