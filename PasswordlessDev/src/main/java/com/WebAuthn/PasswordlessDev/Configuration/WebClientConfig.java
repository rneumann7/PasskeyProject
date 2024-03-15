package com.WebAuthn.PasswordlessDev.Configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Value("${PASSWORDLESS_API_KEY}")
    private String pwlApiKey;

    @Value("${PASSWORDLESS_API_SECRET}")
    private String pwlApiSecret;

    @Bean
    public WebClient webClient() {
        return WebClient.builder()
                .baseUrl("https://v4.passwordless.dev")
                .defaultHeaders(httpHeaders -> {
                    httpHeaders.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
                    httpHeaders.add("ApiSecret", pwlApiSecret);
                    httpHeaders.add("ApiKey", pwlApiKey);
                })
                .build();
    }
}
