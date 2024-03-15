package com.WebAuthn.PasswordlessDev.Services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.WebAuthn.PasswordlessDev.Models.LoginBeginPayload;
import com.WebAuthn.PasswordlessDev.Models.LoginCompletePayload;
import com.WebAuthn.PasswordlessDev.Models.RegBeginPayload;
import com.WebAuthn.PasswordlessDev.Models.RegCompletePayload;
import com.WebAuthn.PasswordlessDev.Models.ServerPublicKeyCredentialCreationOptionsRequest;
import com.WebAuthn.PasswordlessDev.Models.TokenDTO;

import reactor.core.publisher.Mono;

@Service
public class PasswordlessDevService {

    private final WebClient webClient;

    @Autowired
    public PasswordlessDevService(WebClient webClient) {
        this.webClient = webClient;
    }

    // This method will call the Passwordless.Dev API to begin the registration and
    // get the options
    public Mono<String> retrieveRegOptions(RegBeginPayload payload) {
        return webClient.post()
                .uri("/register/begin")
                .body(Mono.just(payload), RegBeginPayload.class)
                .retrieve()
                .bodyToMono(String.class);
    }

    // This method will call the Passwordless.Dev API to complete the registration
    public Mono<String> completeRegistration(RegCompletePayload payload) {
        return webClient.post()
                .uri("/register/complete")
                .body(Mono.just(payload), RegCompletePayload.class)
                .retrieve()
                .bodyToMono(String.class);
    }

    // This method will call the Passwordless.Dev API to retrieve a token for the
    // user
    public Mono<TokenDTO> retrieveRegistrationToken(ServerPublicKeyCredentialCreationOptionsRequest payload) {
        return webClient.post()
                .uri("/register/token")
                .body(Mono.just(payload), ServerPublicKeyCredentialCreationOptionsRequest.class)
                .retrieve()
                .bodyToMono(TokenDTO.class);
    }

    // This method will call the Passwordless.Dev API to begin the sign in
    // process and get the options
    public Mono<String> retrieveLoginOptions(LoginBeginPayload payload) {
        return webClient.post()
                .uri("/signin/begin")
                .body(Mono.just(payload), LoginBeginPayload.class)
                .retrieve()
                .bodyToMono(String.class);
    }

    // This method will call the Passwordless.Dev API to complete the sign in
    // process
    public Mono<String> completeLogin(LoginCompletePayload payload) {
        return webClient.post()
                .uri("/signin/complete")
                .body(Mono.just(payload), LoginCompletePayload.class)
                .retrieve()
                .bodyToMono(String.class);
    }

    // This method will call the Passwordless.Dev API to validate the verification
    // token
    public Mono<String> validateToken(TokenDTO payload) {
        return webClient.post()
                .uri("/signin/verify")
                .body(Mono.just(payload), TokenDTO.class)
                .retrieve()
                .bodyToMono(String.class);
    }

}
