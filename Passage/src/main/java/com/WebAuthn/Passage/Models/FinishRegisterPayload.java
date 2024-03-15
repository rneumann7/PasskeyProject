package com.WebAuthn.Passage.Models;

public class FinishRegisterPayload {

    private ServerAuthenticatorAttestationResponse handshake_response;
    private String user_id;
    private String handshake_id;

    public FinishRegisterPayload() {
    }

    public FinishRegisterPayload(
            String handshake_id,
            ServerAuthenticatorAttestationResponse handshake_response,
            String user_id) {
        this.handshake_response = handshake_response;
        this.handshake_id = handshake_id;
        this.user_id = user_id;
    }

    public ServerAuthenticatorAttestationResponse getHandshake_response() {
        return handshake_response;
    }

    public void setHandshake_response(ServerAuthenticatorAttestationResponse handshake_response) {
        this.handshake_response = handshake_response;
    }

    public String getUser_id() {
        return user_id;
    }

    public void setUser_id(String user_id) {
        this.user_id = user_id;
    }

    public String getHandshake_id() {
        return handshake_id;
    }

    public void setHandshake_id(String handshake_id) {
        this.handshake_id = handshake_id;
    }

}
