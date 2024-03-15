package com.WebAuthn.PasswordlessDev.Models;

public class RegCompletePayload {

    private ServerAuthenticatorAttestationResponse response;
    private String RPID;
    private String Origin;
    private String session;
    private String nickname;

    public RegCompletePayload(ServerAuthenticatorAttestationResponse resp, String RPID, String Origin, String Session,
            String nickname) {
        this.response = resp;
        this.RPID = RPID;
        this.Origin = Origin;
        this.session = Session;
        this.nickname = nickname;
    }

    public RegCompletePayload() {

    }

    public ServerAuthenticatorAttestationResponse getResponse() {
        return response;
    }

    public void setResponse(ServerAuthenticatorAttestationResponse response) {
        this.response = response;
    }

    public String getRPID() {
        return RPID;
    }

    public void setRPID(String rPID) {
        this.RPID = rPID;
    }

    public String getOrigin() {
        return Origin;
    }

    public void setOrigin(String origin) {
        this.Origin = origin;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

}
