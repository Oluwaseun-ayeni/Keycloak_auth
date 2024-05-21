package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	KeycloakBaseURL      = "http://localhost:8080"
	Realm                = "Test"
	KeycloakClientID     = "Wallet-test"
	KeycloakClientSecret = "kYZuoM13FjxSmIjRcSMf8Ujz9UHC7NC6"
)

type KLoginPayload struct {
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
}

type KLoginRes struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type UserInfo struct {
	Username string `json:"preferred_username"`
}

func main() {
	client := &http.Client{}

	// Test login
	payload := &KLoginPayload{
		ClientID:     KeycloakClientID,
		ClientSecret: KeycloakClientSecret,
		Username:     "test-wallet",
		Password:     "Password",
	}
	issueTime := time.Now()
	loginRes, err := login(client, payload)
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return
	}

	fmt.Printf("Login successful: %v\n", loginRes.AccessToken)

	// Check if the token is still active
	if time.Since(issueTime).Seconds() < float64(loginRes.ExpiresIn) {
		// The token is still active
		userInfo, err := extractUserInfo(client, loginRes.AccessToken)
		if err != nil {
			fmt.Printf("Extract user info failed: %v\n", err)
			return
		}
		fmt.Printf("User info: %+v\n", userInfo)
	} else {
		// The token has expired
		fmt.Println("The token has expired. Please login again.")
	}
}

func login(client *http.Client, payload *KLoginPayload) (*KLoginRes, error) {
	formData := url.Values{
		"client_id":     {payload.ClientID},
		"client_secret": {payload.ClientSecret},
		"grant_type":    {"password"},
		"username":      {payload.Username},
		"password":      {payload.Password},
		"scope":         {"openid profile email"},
	}
	encodedFormData := formData.Encode()

	loginURL := KeycloakBaseURL + "/realms/" + Realm + "/protocol/openid-connect/token"
	req, err := http.NewRequest("POST", loginURL, strings.NewReader(encodedFormData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to login user, status code: %s, body: %s", resp.Status, string(body))
	}

	loginRes := &KLoginRes{}
	err = json.NewDecoder(resp.Body).Decode(loginRes)
	if err != nil {
		return nil, err
	}

	return loginRes, nil
}

func extractUserInfo(client *http.Client, accessToken string) (*UserInfo, error) {
	userInfoURL := KeycloakBaseURL + "/realms/" + Realm + "/protocol/openid-connect/userinfo"
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to extract user info, status code: %s, body: %s", resp.Status, string(body))
	}

	userInfo := &UserInfo{}
	err = json.NewDecoder(resp.Body).Decode(userInfo)
	if err != nil {
		return nil, err
	}

	return userInfo, nil
}
