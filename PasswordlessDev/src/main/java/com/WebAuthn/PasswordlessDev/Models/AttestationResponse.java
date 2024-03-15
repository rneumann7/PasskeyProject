package com.WebAuthn.PasswordlessDev.Models;

public class AttestationResponse {

    private String clientDataJSON;
    private String attestationObject;

    public AttestationResponse() {
    }

    public String getAttestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(String attestationObject) {
        this.attestationObject = attestationObject;
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public void setClientDataJSON(String clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

}
