package test

import (
	"testTool"
	"testTool/virtualwebauthn"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test that the registration options received from the relying party server are correct
func TestRegistrationOptions(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// Ensure that the mock credential isn't excluded by the attestation options
	isExcluded := ctx.Credential.IsExcludedForAttestation(*registrationOptions)
	require.False(t, isExcluded)
	// Ensure that the Relying Party details match
	require.Equal(t, ctx.WebauthnDomain, registrationOptions.RelyingPartyID)
	require.Equal(t, ctx.WebauthnDisplayName, registrationOptions.RelyingPartyName)
	// Ensure that the user details match
	require.Equal(t, ctx.UserName, registrationOptions.UserName)
	require.Equal(t, ctx.UserDisplayName, registrationOptions.UserDisplayName)
	// Ensure challenge is contained in response
	require.Greater(t, len(registrationOptions.Challenge), 0)
	// Ensure that the public key parameters are contained in response
	require.Greater(t, len(registrationOptions.PublicKeyCredentialParameters), 0)
}

// Test that the registration options cannot be created without a username
func TestRegistrationOptionsFailure(t *testing.T) {
	ctx := testTool.Setup()
	// set username to empty string
	ctx.UserName = ""
	_, err := testTool.SendAttestationOptionsRequest(t, ctx)
	require.Error(t, err)
}

// Test that the registration options received with
// preference for server-side-credential from the relying party server are correct
func TestServerSideCredOption(t *testing.T) {
	ctx := testTool.Setup()
	ctx.RKOption = "discouraged"
	ctx.TestFlags.RequireRK = false
	testTool.GetRegistrationOptions(t, ctx)
}

// Test that the relying party rejects an attestation response with
// the incorrect client data type "webauthn.get".
// Correct would be: "webauthn.create"
func TestRegClientDataType(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// create attestation response with wrong type
	ctx.TestFlags.WrongType = true
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an attestation response with a
// different challenge than the one received in the registration options
func TestRegChallengeVerification(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// Change challenge to different challenge
	registrationOptions.Challenge = []byte("some challenge")
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an attestation response with a
// different origin than the one set for the the relying party server
func TestRegOriginVerification(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// Change origin to a different origin
	ctx.RelyingParty.Origin = "http://wrongorigin"
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an attestation response with a
// different relying party id than the one set for the the relying party server
func TestRegRpIDVerification(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// Change rpID to a different rpID
	ctx.RelyingParty.ID = "wrong rpID"
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party fails the registration flow
// when user presence flag is not set to true
func TestRegUserPresentFlag(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// Set user present flag to false
	ctx.Authenticator.Options.UserPresent = false
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party fails the registration flow
// when user verification is required but the user verification flag is not set to true
func TestRegUserVerifiedFlag(t *testing.T) {
	ctx := testTool.Setup()
	// Set user verified flag to false
	ctx.Authenticator.Options.UserVerified = false
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an attestation response with a
// false cose algorithm for the public key
func TestRegCOSEAlgVerification(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// create attestation response with an unsupported COSE algorithm
	ctx.TestFlags.WrongCOSEAlg = true
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an attestation response with a
// different algorithm for sigining the attestation than the one given in the attestation options
func TestPackedAttestationAlgVerification(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// create attestation response with a false alg
	ctx.TestFlags.WrongAlg = true
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an attestation response with a
// false signature
func TestPackedAttestationSignatureVerification(t *testing.T) {
	ctx := testTool.Setup()
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// create attestation response with a false signature
	ctx.TestFlags.WrongSig = true
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the registration is successful when the
// packed attestation certificate that trusted
func TestPackedAttestationCertTrust(t *testing.T) {
	ctx := testTool.Setup()
	ctx.Authenticator.ReadCertificateFromFile("../keys_certs/cert.pem")
	ctx.Authenticator.ReadKeyFromFile("../keys_certs/key.pem")
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// create attestation response with a false signature
	ctx.TestFlags.CertAttestation = true
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.NoError(t, err)
}

// Test that the relying party rejects an attestation response with an
// packed attestation certificate that is not trusted
func TestPackedAttestationCertTrustFail(t *testing.T) {
	ctx := testTool.Setup()
	ctx.Authenticator.ReadCertificateFromFile("../keys_certs/untrusted_cert.pem")
	ctx.Authenticator.ReadKeyFromFile("../keys_certs/untrusted_key.pem")
	registrationOptions := testTool.GetRegistrationOptions(t, ctx)
	// create attestation response with a false signature
	ctx.TestFlags.CertAttestation = true
	attestationResponse := virtualwebauthn.CreateAttestationResponse(ctx.RelyingParty, ctx.Authenticator, ctx.Credential, *registrationOptions, ctx.TestFlags)
	// send attestation response to relying party server and require failure
	_, err := testTool.SendAttestationResponse(t, attestationResponse)
	require.Error(t, err)
}

// Test that the relying party rejects an attestation response with a
// non empty attestation statement
func TestNoneAttestationFail(t *testing.T) {
	ctx := testTool.Setup()
	ctx.TestFlags.NoneAttestation = true
	ctx.TestFlags.WrongNoneAttestation = true
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.Error(t, err)
}

// Test a successful registration flow with the none attestation
func TestNoneAttestation(t *testing.T) {
	ctx := testTool.Setup()
	ctx.TestFlags.NoneAttestation = true
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
}

// Test a successful registration flow
func TestSuccessfulRegistration(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
}

// Test duplicate registration
func TestCredentialAlreadyRegistered(t *testing.T) {
	ctx := testTool.Setup()
	err := testTool.ExecuteRegistrationFlow(t, ctx)
	require.NoError(t, err)
	ctx.UserName = testTool.GenerateUniqueUsername()
	err2 := testTool.ExecuteRegistrationFlow(t, ctx)
	require.Error(t, err2)
}
