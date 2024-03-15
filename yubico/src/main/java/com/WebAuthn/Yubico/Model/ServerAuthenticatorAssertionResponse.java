package com.WebAuthn.Yubico.Model;

public class ServerAuthenticatorAssertionResponse {

    private String id;
    private String rawId;
    private String type;
    private AssertionResponse response;
    private ClientExtensionResults clientExtensionResults;

    public ServerAuthenticatorAssertionResponse() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRawId() {
        return rawId;
    }

    public void setRawId(String rawId) {
        this.rawId = rawId;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public AssertionResponse getResponse() {
        return response;
    }

    public void setResponse(AssertionResponse response) {
        this.response = response;
    }

    public ClientExtensionResults getClientExtensionResults() {
        return clientExtensionResults;
    }

    public void setClientExtensionResults(ClientExtensionResults clientExtensionResults) {
        this.clientExtensionResults = clientExtensionResults;
    }

}
