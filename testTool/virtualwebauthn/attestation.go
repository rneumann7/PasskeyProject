package virtualwebauthn

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

/// Options

type AttestationOptions struct {
	Challenge                     []byte                            `json:"challenge,omitempty"`
	ExcludeCredentials            []string                          `json:"excludeCredentials,omitempty"`
	RelyingPartyID                string                            `json:"rpId,omitempty"`
	RelyingPartyName              string                            `json:"rpName,omitempty"`
	UserID                        string                            `json:"user,omitempty"`
	UserName                      string                            `json:"userName,omitempty"`
	UserDisplayName               string                            `json:"userDisplayName,omitempty"`
	PublicKeyCredentialParameters []int                             `json:"pubKeyCredParams,omitempty"`
	AuthenticatorSelection        attestationAuthenticatorSelection `json:"authenticatorSelection,omitempty"`
	Extensions                    attestationExtensions             `json:"extensions,omitempty"`
}

func ParseAttestationOptions(str string, testFlags TestFlags) (attestationOptions *AttestationOptions, err error) {
	values := attestationOptionsValues{}
	err = json.Unmarshal([]byte(str), &values)
	if err != nil {
		return nil, err
	}
	if values.PublicKey != nil {
		values = *values.PublicKey
	}

	attestationOptions = &AttestationOptions{
		RelyingPartyID:   values.RP.ID,
		RelyingPartyName: values.RP.Name,
	}

	decodedUserID, err := base64.RawURLEncoding.DecodeString(values.User.ID)
	if err != nil {
		return nil, errors.New("failed to decode user id in response")
	}

	attestationOptions.UserID = string(decodedUserID)
	attestationOptions.UserName = values.User.Name
	attestationOptions.UserDisplayName = values.User.DisplayName

	if len(values.Challenge) == 0 {
		return nil, errors.New("failed to find challenge in response")
	}
	challenge, err := base64.RawURLEncoding.DecodeString(values.Challenge)
	if err != nil {
		return nil, err
	}
	attestationOptions.Challenge = challenge

	for _, cred := range values.ExcludeCredentials {
		if len(cred.ID) == 0 {
			return nil, errors.New("allowed credential has an empty id")
		}
		attestationOptions.ExcludeCredentials = append(attestationOptions.ExcludeCredentials, cred.ID)
	}

	for _, param := range values.PublicKeyCredParams {
		if param.Type != "public-key" {
			return nil, errors.New("param is of the wrong type")
		}
		attestationOptions.PublicKeyCredentialParameters = append(attestationOptions.PublicKeyCredentialParameters, param.Algorithm)
	}

	// parse extensions
	if credProps, ok := values.Extensions["credProps"].(bool); ok {
		attestationOptions.Extensions.CredProps.RK = credProps
	} else {
		// do nothing when not aviailable
	}

	// check requireRk and residentKey is set correct, when server-side-credential was requested
	if testFlags.RequireRK == false {
		if values.AuthenticatorSelection.RequireRK || values.AuthenticatorSelection.ResidentKey == "required" {
			return nil, errors.New("Server-Side-Credential login not supported")
		}
	}

	return attestationOptions, nil
}

/// Response

func CreateAttestationResponse(rp RelyingParty, auth Authenticator, cred Credential, options AttestationOptions, testFlags TestFlags) string {

	// check if server-side-credential needs to be created
	if testFlags.RequireRK == false {
		// create server side credential
		pkcs := PublicKeyCredentialSource{
			Type:       "public-key",
			Credential: cred,
			RpID:       rp.ID,
		}
		// encrypt the credential
		credId, _ := encryptCredential(pkcs, auth.MasterKey)
		// set credential id to credId
		cred.ID = credId
	}

	// Change type to wrong type for testing
	cDataType := "webauthn.create"
	if testFlags.WrongType {
		cDataType = "webauthn.get"
	}

	var clientData ClientDataInterface = clientData{
		Type:      cDataType,
		Challenge: base64.RawURLEncoding.EncodeToString(options.Challenge),
		Origin:    rp.Origin,
	}

	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		panic("failed to marshal json")
	}
	clientDataJSONEncoded := base64.RawURLEncoding.EncodeToString(clientDataJSON)

	// For Testing: If wrongCOSEAlg is true, then a wrong algorithm for the public key COSE is used.
	publicKeyData := cred.Key.AttestationData(testFlags.WrongCOSEAlg)

	credData := []byte{}
	credData = append(credData, auth.Aaguid[:]...)
	credData = append(credData, bigEndianBytes(len(cred.ID), 2)...)
	credData = append(credData, cred.ID...)
	credData = append(credData, publicKeyData...)

	rpIDHash := sha256.Sum256([]byte(rp.ID))
	flags := authenticatorDataFlags(auth.Options.UserPresent, auth.Options.UserVerified, true, false)

	authData := []byte{}
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, bigEndianBytes(cred.Counter, 4)...)
	authData = append(authData, credData...)

	clientDataJSONHashed := sha256.Sum256(clientDataJSON)
	verifyData := append(authData, clientDataJSONHashed[:]...)

	hasher := crypto.SHA256.New()
	hasher.Write(verifyData)
	digest := hasher.Sum(nil)

	sig, err := cred.Key.Sign(digest)
	if err != nil {
		panic("failed to sign digest")
	}

	var algo int
	if cred.Key.Type == KeyTypeEC2 {
		algo = ec2SHA256Algo
	} else if cred.Key.Type == KeyTypeRSA {
		algo = rsaSHA256Algo
	}

	// Change algorithm to wrong algorithm for testing
	if testFlags.WrongAlg {
		algo = 0
	}

	// Change signature to wrong signature for testing
	if testFlags.WrongSig {
		sig[0] = sig[0] + 3
	}

	var attestationObject AttestationObjectInterface = attestationObject{
		Format:   "packed",
		AuthData: authData,
		Statement: attestationStatement{
			Algorithm: algo,
			Signature: sig,
		},
	}
	// Create none attestation object for testing
	if testFlags.NoneAttestation {
		emptyMap := make(map[string]int)
		if testFlags.WrongNoneAttestation {
			emptyMap["alg"] = 0
		}
		attestationObject = attestationObjectNone{
			Format:    "none",
			Statement: emptyMap,
			AuthData:  authData,
		}
	}
	// Create x5c attestation object for testing
	if testFlags.CertAttestation {
		sig, err := auth.Sign(digest)
		if err != nil {
			panic("failed to sign digest")
		}
		attestationObject = attestationObjectCert{
			Format: "packed",
			Statement: attestationStatementCert{
				Algorithm: auth.Alg,
				Signature: sig,
				X5c:       [][]byte{auth.AttestationCert},
			},
			AuthData: authData,
		}
	}

	attestationObjectBytes := marshalCbor(attestationObject)
	attestationObjectEncoded := base64.RawURLEncoding.EncodeToString(attestationObjectBytes)

	credIDEncoded := base64.RawURLEncoding.EncodeToString(cred.ID)

	attestationResponse := AttestationResponse{
		AttestationObject: attestationObjectEncoded,
		ClientDataJSON:    clientDataJSONEncoded,
	}

	// Create empty client extension results
	clientExtensionResults := attestationExtensions{}

	// Set credProps extension if requested in attestation options
	if options.Extensions.CredProps.RK == true {
		clientExtensionResults = attestationExtensions{
			CredProps: credPropsExt{
				RK: testFlags.RequireRK,
			},
		}
	}

	attestationResult := AttestationResult{
		Type:                   "public-key",
		ID:                     credIDEncoded,
		RawID:                  credIDEncoded,
		Response:               attestationResponse,
		ClientExtensionResults: clientExtensionResults,
	}

	attestationResultBytes, err := json.Marshal(attestationResult)
	if err != nil {
		panic("failed to marshal json")
	}

	return string(attestationResultBytes)
}

/// Helpers

type attestationOptionsValues struct {
	Challenge              string                                   `json:"challenge,omitempty"`
	AuthenticatorSelection attestationAuthenticatorSelection        `json:"authenticatorSelection,omitempty"`
	Attestation            string                                   `json:"attestation,omitempty"`
	ExcludeCredentials     []attestationOptionsExcludeCredential    `json:"excludeCredentials,omitempty"`
	RP                     attestationOptionsRelyingParty           `json:"rp,omitempty"`
	User                   attestationOptionsUser                   `json:"user,omitempty"`
	PublicKeyCredParams    []attestationsOptionsPublicKeyCredParams `json:"pubKeyCredParams,omitempty"`
	PublicKey              *attestationOptionsValues                `json:"publicKey,omitempty"`
	Extensions             map[string]interface{}                   `json:"extensions,omitempty"`
}

type attestationAuthenticatorSelection struct {
	RequireRK               bool   `json:"requireResidentKey,omitempty"`
	ResidentKey             string `json:"residentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
}

type attestationExtensions struct {
	CredProps credPropsExt `json:"credProps,omitempty"`
}
type credPropsExt struct {
	RK interface{} `json:"rk,omitempty"`
}

type attestationsOptionsPublicKeyCredParams struct {
	Algorithm int    `json:"alg"`
	Type      string `json:"type"`
}

type attestationOptionsRelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type attestationOptionsUser struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type attestationOptionsExcludeCredential struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type attestationStatement struct {
	Algorithm int    `json:"alg"`
	Signature []byte `json:"sig"`
}

type attestationStatementCert struct {
	Algorithm int      `json:"alg"`
	Signature []byte   `json:"sig"`
	X5c       [][]byte `json:"x5c"`
}
type attestationObjectNone struct {
	Format    string         `json:"fmt"`
	Statement map[string]int `json:"attStmt"`
	AuthData  []byte         `json:"authData"`
}

type attestationObject struct {
	Format    string               `json:"fmt"`
	Statement attestationStatement `json:"attStmt"`
	AuthData  []byte               `json:"authData"`
}

type attestationObjectCert struct {
	Format    string                   `json:"fmt"`
	Statement attestationStatementCert `json:"attStmt"`
	AuthData  []byte                   `json:"authData"`
}

type AttestationResponse struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

type AttestationResult struct {
	Type                   string                `json:"type"`
	ID                     string                `json:"id"`
	RawID                  string                `json:"rawId"`
	Response               AttestationResponse   `json:"response"`
	ClientExtensionResults attestationExtensions `json:"clientExtensionResults"`
}

type AttestationObjectInterface interface{}
