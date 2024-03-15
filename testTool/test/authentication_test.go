package test

import (
	"testTool"
	"testTool/virtualwebauthn"
	"testing"

	_ "github.com/fxamacker/webauthn/packed"
	"github.com/stretchr/testify/require"
)

// Test that the authentication options received from the relying party server are correct
func TestAuthenticationOptions(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// Ensure challenge is contained in response
	require.Greater(t, len(authenticationOptions.Challenge), 0)
}

// Test that the authentication options received from the relying party server are correct
func TestAuthenticationOptionsFailure(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	// set username to empty string
	ctx.UserName = ""
	_, err = testTool.SendAssertionOptionsRequest(t, ctx)
	require.Error(t, err)
}

// Test that the relying party server rejects an assertion response
// with a credential ID not listed in allowCredentials
func TestCredIDVerification(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// create assertion response with wrong credID
	ctx.Credential.ID = []byte("wrong credID")
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test that the relying party server fails the authentication flow
// when the userhandle given does not own the credential
func TestAuthUserHandleDoesNotOwnCredential(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// Set userhandle to a different userhandle
	ctx.Authenticator.Options.UserHandle = []byte("wrong userhandle")
	// create assertion response
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an assertion response with
// the incorrect client data type "webauthn.create".
// Correct would be: "webauthn.get"
func TestAuthClientDataType(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// create assertion response with wrong type
	ctx.TestFlags.WrongType = true
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an assertion response with a
// different challenge than the one received in the authentication options
func TestAuthChallengeVerification(t *testing.T) {
	ctx := testTool.Setup()
	// make successful registration
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	// get authentication options
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// Change challenge to different challenge
	authenticationOptions.Challenge = []byte("some challenge")
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an assertion response with a
// different origin than the one set for the the relying party server
func TestAuthOriginVerification(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// Change origin to a different origin
	ctx.RelyingParty.Origin = "http://wrongorigin"
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an assertion response with a
// different relying party id than the one set for the the relying party server
func TestAuthRpIDVerification(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// Change rpID to a different rpID
	ctx.RelyingParty.ID = "wrong rpID"
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test that the relying party fails the authentication flow
// when user presence flag is not set to true
func TestAuthUserPresentFlag(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// Set user present flag to false
	ctx.Authenticator.Options.UserPresent = false
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test that the relying party fails the authentication flow
// when user verification is required but the user verification flag is not set to true
func TestAuthUserVerifiedFlag(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// Set user verified flag to false and create assertion response
	ctx.Authenticator.Options.UserVerified = false
	attestationResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party fails the authentication flow
// when the signature of the assertion response is incorrect
func TestAuthSignatureVerification(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// create assertion response with wrong signature
	ctx.TestFlags.WrongSig = true
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test that the relying party fails the authentication flow
// when the signature count of the assertion response is incorrect
func TestAuthCounterVerification(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	// do one successful authentication, to increase counter of rp
	err = testTool.ExecuteAuthenticationFlow(t, ctx)
	require.NoError(t, err)
	// do another authentication flow with wrong counter
	authenticationOptions := testTool.GetAuthenticationOptions(t, ctx)
	// create assertion response with wrong counter
	ctx.Credential.Counter = 0
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *authenticationOptions, ctx.TestFlags)
	// send assertion response to relying party server and require failure
	_, err = testTool.SendAssertionResponse(t, assertionResponse)
	require.Error(t, err)
}

// Test a successful authentication flow with a resident key
func TestSuccessfulAuthentication(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	err = testTool.ExecuteAuthenticationFlow(t, ctx)
	require.NoError(t, err)
}
