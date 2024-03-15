package com.WebAuthn.Yubico.Model;

public class ServerPublicKeyCredentialGetOptionsRequest {

    private String username;
    private String userVerification;

    public ServerPublicKeyCredentialGetOptionsRequest() {
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
