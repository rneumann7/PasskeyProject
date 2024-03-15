package testTool

import (
	"encoding/json"
	"testTool/virtualwebauthn"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestContext is a struct that holds all the information needed to run a test.
type TestContext struct {
	WebauthnDisplayName string
	WebauthnDomain      string
	WebauthnOrigin      string
	UserName            string
	UserDisplayName     string
	UserID              string
	RKOption            string
	UVOption            string
	RelyingParty        virtualwebauthn.RelyingParty
	Authenticator       virtualwebauthn.Authenticator
	Credential          virtualwebauthn.Credential
	DelayDuration       int
	TestFlags           virtualwebauthn.TestFlags
}

// sets up a new test context for a test
func Setup() *TestContext {
	uniqueUsername := GenerateUniqueUsername()
	rkOption := "required"
	uvOption := "required"
	ctx := &TestContext{
		WebauthnDisplayName: "localhost",
		WebauthnDomain:      "localhost",
		// All app except passwordless.dev need localhost:8080
		WebauthnOrigin:  "http://localhost:8080",
		UserName:        uniqueUsername,
		UserDisplayName: uniqueUsername,
		UserID:          generateUniqueUserID(),
		RKOption:        rkOption,
		UVOption:        uvOption,
		RelyingParty:    virtualwebauthn.RelyingParty{},
		Authenticator:   virtualwebauthn.NewAuthenticator(),
		// Alternative key type : KeyTypeRSA
		Credential:    virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2),
		DelayDuration: 0, // wait between tests, to avoid rate limiting when testing toolkits
		TestFlags:     virtualwebauthn.TestFlags{RequireRK: isResidentKeyRequired(rkOption)},
	}
	// set relying party details
	ctx.RelyingParty = virtualwebauthn.RelyingParty{
		Name:   ctx.WebauthnDisplayName,
		ID:     ctx.WebauthnDomain,
		Origin: ctx.WebauthnOrigin}
	return ctx
}

// gets the registration options from the relying party server
func GetRegistrationOptions(t *testing.T, ctx *TestContext) *virtualwebauthn.AttestationOptions {
	// send attestation options request to relying party server and get response
	optionsJSON, _ := SendAttestationOptionsRequest(t, ctx)
	// parse response
	attestationOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON), ctx.TestFlags)
	require.NoError(t, err)
	require.NotNil(t, attestationOptions)
	// save UserID from response
	ctx.UserID = attestationOptions.UserID
	return attestationOptions
}

// gets the authentication options from the relying party server
func GetAuthenticationOptions(t *testing.T, ctx *TestContext) *virtualwebauthn.AssertionOptions {
	// send assertion options request to relying party server and get response
	optionsJSON, _ := SendAssertionOptionsRequest(t, ctx)
	// parse response
	assertionOptions, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
	require.NoError(t, err)
	require.NotNil(t, assertionOptions)
	// Ensure that the mock authenticator has a valid credential that was requested by the assertion
	// options
	// foundCredential := ctx.Authenticator.FindAllowedCredential(*assertionOptions)
	// require.NotNil(t, foundCredential)
	return assertionOptions
}

// does a full registration flow, from getting the attestation options, sending the attestation response
// and adding the credential to the authenticator
func ExecuteRegistrationFlow(t *testing.T, ctx *TestContext) error {
	// get registration options
	attestationOptions := GetRegistrationOptions(t, ctx)
	// create attestation response
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *attestationOptions, ctx.TestFlags)
	// send attestation response to relying party server
	_, err := SendAttestationResponse(t, attestationResponse)
	// Add the userID to the mock authenticator so it can return it in assertion responses.
	ctx.Authenticator.Options.UserHandle = []byte(ctx.UserID)
	// Add the EC2 credential to the mock authenticator if it is a resident key
	if ctx.TestFlags.RequireRK == true {
		ctx.Authenticator.AddCredential(ctx.Credential)
	}
	return err
}

// does a full authentication flow, from getting the authentication option to sending the authentication response
func ExecuteAuthenticationFlow(t *testing.T, ctx *TestContext) error {
	// get assertion options
	assertionOptions := GetAuthenticationOptions(t, ctx)
	// create assertion response
	assertionResponse := virtualwebauthn.CreateAssertionResponse(ctx.RelyingParty, ctx.Authenticator, &ctx.Credential, *assertionOptions, ctx.TestFlags)
	// send assertion response to relying party server
	_, err := SendAssertionResponse(t, assertionResponse)
	return err
}

// converts to json string
func convertToJsonString(data interface{}) string {
	attestationResultBytes, err := json.Marshal(data)
	if err != nil {
		panic("failed to marshal json")
	}
	return string(attestationResultBytes)
}

// generates an unique username and displayname
func GenerateUniqueUsername() string {
	return uuid.New().String() + "@example.com"
}

// generate an unique userId
func generateUniqueUserID() string {
	return uuid.New().String()
}

// checks if resident key is required
func isResidentKeyRequired(rk string) bool {
	return rk == "required"
}
