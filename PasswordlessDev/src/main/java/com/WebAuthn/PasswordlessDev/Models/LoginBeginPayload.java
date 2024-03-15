package com.WebAuthn.PasswordlessDev.Models;

public class LoginBeginPayload {

    private String origin;
    private String UserId;
    private String userVerification;
    private String rpid;

    public LoginBeginPayload(String origin, String userId, String userVerification, String rpid) {
        this.origin = origin;
        this.UserId = userId;
        this.userVerification = userVerification;
        this.rpid = rpid;
    }

    public LoginBeginPayload() {

    }

    public String getUserId() {
        return UserId;
    }

    public void setUserId(String userId) {
        this.UserId = userId;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public String getUserVerification() {
        return userVerification;
    }

    public void setUserVerification(String userVerification) {
        this.userVerification = userVerification;
    }

    public String getRpid() {
        return rpid;
    }

    public void setRpid(String rpid) {
        this.rpid = rpid;
    }

}
