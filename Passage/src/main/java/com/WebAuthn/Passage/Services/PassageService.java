package com.WebAuthn.Passage.Services;

import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import com.WebAuthn.Passage.Models.FinishLoginPayload;
import com.WebAuthn.Passage.Models.FinishRegisterPayload;
import com.WebAuthn.Passage.Models.StartPayload;

import reactor.core.publisher.Mono;

@Service
public class PassageService {

    private final WebClient webClientPassage;

    @Autowired
    public PassageService(WebClient webClientPassage) {
        this.webClientPassage = webClientPassage;
    }

    // Call the Passsage Auth API to begin the registration and
    // get the options
    public Mono<String> retrieveRegistrationOptions(StartPayload payload) {
        return webClientPassage.post()
                .uri("/register/webauthn/start")
                .body(Mono.just(payload), StartPayload.class)
                .retrieve()
                .bodyToMono(String.class);
    }

    // Call the Passsage Auth API to finish the registration
    public Mono<String> finishRegistration(FinishRegisterPayload payload) {
        return webClientPassage.post()
                .uri("/register/webauthn/finish")
                .body(Mono.just(payload), FinishRegisterPayload.class)
                .retrieve()
                .bodyToMono(String.class);
    }

    // Call the Passsage Auth API to begin the login and
    // get the options
    public Mono<String> retrieveLoginOptions(StartPayload payload) {
        return webClientPassage.post()
                .uri("/login/webauthn/start")
                .body(Mono.just(payload), StartPayload.class)
                .retrieve()
                .bodyToMono(String.class);
    }

    // Call the Passsage Auth API to finish the login
    public Mono<String> finishLogin(FinishLoginPayload payload) {
        return webClientPassage.post()
                .uri("/login/webauthn/finish")
                .body(Mono.just(payload), FinishLoginPayload.class)
                .retrieve()
                .bodyToMono(String.class);
    }
}
