package com.WebAuthn.Passage.Models;

public class StartPayload {

    private String identifier;

    public StartPayload() {
    }

    public StartPayload(String identifier) {
        this.identifier = identifier;
        // if identifier does not contain an @ and is not empty, add an email ending
        // Empty identifier means it is a discoverable credential login
        if (!identifier.contains("@") && !identifier.equals(""))
            this.identifier = identifier + "@example.com";
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

}
