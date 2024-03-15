package com.WebAuthn.PasswordlessDev.Models;

public class ServerPublicKeyCredentialGetOptionsRequest {

    private String username;
    private String userId;
    private String userVerification;

    public ServerPublicKeyCredentialGetOptionsRequest() {
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUserVerification() {
        return userVerification;
    }

    public void setUserVerification(String userVerification) {
        this.userVerification = userVerification;
    }

}
