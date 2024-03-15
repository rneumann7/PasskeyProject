package com.WebAuthn.PasswordlessDev.Models;

public class TokenDTO {

    private String token;

    public TokenDTO() {

    }

    public TokenDTO(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
