package com.WebAuthn.Passage.Models;

public class AttestationResponse {

    private String clientDataJSON;
    private String attestationObject;

    public AttestationResponse() {
    }

    public String getClientDataJSON() {
        return clientDataJSON;
    }

    public void setClientDataJSON(String clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

    public String getAttestationObject() {
        return attestationObject;
    }

    public void setAttestationObject(String attestationObject) {
        this.attestationObject = attestationObject;
    }

}
