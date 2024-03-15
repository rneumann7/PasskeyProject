package com.WebAuthn.Passage.Utility;

import java.util.UUID;

public class EmailGenerator {

    public static String generateRandomEmail() {
        String uuid = UUID.randomUUID().toString();
        return uuid + "@example.com";
    }
}