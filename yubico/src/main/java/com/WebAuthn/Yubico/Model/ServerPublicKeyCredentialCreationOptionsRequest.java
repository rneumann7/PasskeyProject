package com.WebAuthn.Yubico.Model;

import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.ByteArray;
import com.WebAuthn.Yubico.Utility.UUIDGenerator;

@JsonInclude(JsonInclude.Include.NON_NULL) // Don't include null values during serialization to JSON
public class ServerPublicKeyCredentialCreationOptionsRequest {

    @JsonIgnore
    private ByteArray userId;
    private String username;
    private String displayName;
    private String attestation;
    private String authenticatorType;
    private boolean discoverable;
    private String userVerification;
    private String rkOption;

    public ServerPublicKeyCredentialCreationOptionsRequest() {
        this.userId = UUIDGenerator.generateUUIDByteArray();
    }

    // The following are workarounds for mapping fields of the nested object
    @JsonProperty("authenticatorSelection")
    private void unpackNestedObject(Map<String, Object> nested) {
        authenticatorType = (nested.get("authenticatorAttachment") != null)
                ? String.valueOf(nested.get("authenticatorAttachment"))
                : null;
        discoverable = (nested.get("requireResidentKey")) != null
                ? Boolean.valueOf(String.valueOf(nested.get("requireResidentKey")))
                : false;
        userVerification = (nested.get("userVerification") != null) ? String.valueOf(nested.get("userVerification"))
                : "discouraged";
        rkOption = (nested.get("residentKey") != null) ? String.valueOf(nested.get("residentKey"))
                : "discouraged";
    }

    public ByteArray getUserId() {
        return userId;
    }

    public void setUserId(ByteArray userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getAttestation() {
        return attestation;
    }

    public void setAttestation(String attestation) {
        this.attestation = attestation;
    }

    public String getAuthenticatorType() {
        return authenticatorType;
    }

    public void setAuthenticatorType(String authenticatorType) {
        this.authenticatorType = authenticatorType;
    }

    public boolean isDiscoverable() {
        return discoverable;
    }

    public void setDiscoverable(boolean discoverable) {
        this.discoverable = discoverable;
    }

    public String getUserVerification() {
        return userVerification;
    }

    public void setUserVerification(String userVerification) {
        this.userVerification = userVerification;
    }

    public String getRkOption() {
        return rkOption;
    }

    public void setRkOption(String rkOption) {
        this.rkOption = rkOption;
    }

}
