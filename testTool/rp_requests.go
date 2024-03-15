package testTool

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Start of registration flow, returns the attestation options from the relying party server
func SendAttestationOptionsRequest(t *testing.T, ctx *TestContext) (string, error) {
	delay(ctx.DelayDuration)
	authSelection := AuthenticatorSelection{
		RequireRK:        isResidentKeyRequired(ctx.RKOption),
		ResidentKey:      ctx.RKOption,
		UserVerification: ctx.UVOption,
	}
	requestBody := AttestationRequestBody{
		Username:               ctx.UserName,
		DisplayName:            ctx.UserDisplayName,
		UserID:                 ctx.UserID,
		AuthenticatorSelection: authSelection,
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	require.NoError(t, err)
	request, err := http.NewRequest("POST", "http://localhost:8080/attestation/options", bytes.NewBuffer(requestBodyBytes))
	require.NoError(t, err)
	return sendRequest(t, request)
}

// End of registration flow, sends the attestation response from the authenticator to the relying party server
func SendAttestationResponse(t *testing.T, authResponse string) (string, error) {
	requestBody := []byte(authResponse)
	request, err := http.NewRequest("POST", "http://localhost:8080/attestation/result", bytes.NewBuffer(requestBody))
	require.NoError(t, err)
	return sendRequest(t, request)
}

// Start of authentication flow, returns the assertion options from the relying party server
func SendAssertionOptionsRequest(t *testing.T, ctx *TestContext) (string, error) {
	requestBody := AssertionRequestBody{
		Username:         ctx.UserName,
		UserID:           ctx.UserID,
		UserVerification: ctx.UVOption,
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	require.NoError(t, err)
	request, err := http.NewRequest("POST", "http://localhost:8080/assertion/options", bytes.NewBuffer(requestBodyBytes))
	require.NoError(t, err)
	return sendRequest(t, request)
}

// End of authentication flow, sends the assertion response from the authenticator to the relying party server
func SendAssertionResponse(t *testing.T, authResponse string) (string, error) {
	requestBody := []byte(authResponse)
	request, err := http.NewRequest("POST", "http://localhost:8080/assertion/result", bytes.NewBuffer(requestBody))
	require.NoError(t, err)
	return sendRequest(t, request)
}

func sendRequest(t *testing.T, request *http.Request) (string, error) {
	// Set header
	request.Header.Set("Content-Type", "application/json")
	// Make the request
	client := &http.Client{}
	response, err := client.Do(request)
	require.NoError(t, err)

	defer response.Body.Close()
	// Read the response body
	body, err := io.ReadAll(response.Body)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err = errors.New(string(body))
	}
	return string(body), err

}

// delay for a number of seconds
func delay(seconds int) {
	time.Sleep(time.Second * time.Duration(seconds))
}

type AttestationRequestBody struct {
	Username               string                 `json:"username"`
	DisplayName            string                 `json:"displayName,omitempty"`
	UserID                 string                 `json:"userId"`
	ResidentKey            string                 `json:"residentKey,omitempty"`
	UserVerification       string                 `json:"userVerification,omitempty"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection,omitempty"`
}

type AssertionRequestBody struct {
	Username         string `json:"username"`
	UserID           string `json:"userId"`
	UserVerification string `json:"userVerification,omitempty"`
}

type AuthenticatorSelection struct {
	RequireRK        bool   `json:"requireResidentKey,omitempty"`
	ResidentKey      string `json:"residentKey,omitempty"`
	UserVerification string `json:"userVerification,omitempty"`
}
