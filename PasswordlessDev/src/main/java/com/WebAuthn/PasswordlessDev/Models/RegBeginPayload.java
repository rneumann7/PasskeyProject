package com.WebAuthn.PasswordlessDev.Models;

public class RegBeginPayload {

    private String token;
    private String RPID;
    private String Origin;

    public RegBeginPayload(String token, String RPID, String Origin) {
        this.token = token;
        this.RPID = RPID;
        this.Origin = Origin;
    }

    public RegBeginPayload() {

    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getRPID() {
        return RPID;
    }

    public void setRPID(String rPID) {
        RPID = rPID;
    }

    public String getOrigin() {
        return Origin;
    }

    public void setOrigin(String origin) {
        Origin = origin;
    }

}
