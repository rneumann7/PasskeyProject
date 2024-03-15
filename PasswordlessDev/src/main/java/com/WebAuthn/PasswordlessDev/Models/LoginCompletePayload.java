package com.WebAuthn.PasswordlessDev.Models;

public class LoginCompletePayload {

    private String session;
    private String origin;
    private String RPID;
    private ServerAuthenticatorAssertionResponse response;

    public LoginCompletePayload() {
    }

    public LoginCompletePayload(
            ServerAuthenticatorAssertionResponse resp,
            String session,
            String origin,
            String RPID) {
        this.session = session;
        this.response = resp;
        this.origin = origin;
        this.RPID = RPID;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getRPID() {
        return RPID;
    }

    public void setRPID(String rPID) {
        this.RPID = rPID;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public ServerAuthenticatorAssertionResponse getResponse() {
        return response;
    }

    public void setResponse(ServerAuthenticatorAssertionResponse response) {
        this.response = response;
    }

}
