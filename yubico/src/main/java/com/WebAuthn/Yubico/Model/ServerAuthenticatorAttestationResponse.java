package com.WebAuthn.Yubico.Model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL) // Don't include null values during serialization to JSON
public class ServerAuthenticatorAttestationResponse {

    private String id;
    private String rawId;
    private String type;
    private AttestationResponse response;
    private ClientExtensionResults clientExtensionResults;

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

    public ClientExtensionResults getClientExtensionResults() {
        return clientExtensionResults;
    }

    public void setClientExtensionResults(ClientExtensionResults clientExtensionResults) {
        this.clientExtensionResults = clientExtensionResults;
    }
}