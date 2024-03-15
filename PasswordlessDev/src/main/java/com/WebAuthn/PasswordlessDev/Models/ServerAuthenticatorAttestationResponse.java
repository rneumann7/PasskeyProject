package com.WebAuthn.PasswordlessDev.Models;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL) // Don't include null values during serialization to JSON
public class ServerAuthenticatorAttestationResponse {

    private String id;
    private String rawId;
    private String type;
    private AttestationResponse response;
    private ClientExtensionResults extensions;

    public ServerAuthenticatorAttestationResponse() {

    }

    public String getId() {
        return id;
    }

    public String getRawId() {
        return rawId;
    }

    public String getType() {
        return type;
    }

    public AttestationResponse getResponse() {
        return response;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setRawId(String rawId) {
        this.rawId = rawId;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setResponse(AttestationResponse response) {
        this.response = response;
    }

    @JsonGetter("extensions")
    public ClientExtensionResults getExtensions() {
        return extensions;
    }

    @JsonProperty("clientExtensionResults")
    public void setExtensions(ClientExtensionResults extensions) {
        this.extensions = extensions;
    }
}