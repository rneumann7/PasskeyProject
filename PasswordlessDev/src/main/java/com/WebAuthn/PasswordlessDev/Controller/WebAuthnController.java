package com.WebAuthn.PasswordlessDev.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.WebAuthn.PasswordlessDev.Models.LoginBeginPayload;
import com.WebAuthn.PasswordlessDev.Models.LoginCompletePayload;
import com.WebAuthn.PasswordlessDev.Models.RegBeginPayload;
import com.WebAuthn.PasswordlessDev.Models.RegCompletePayload;
import com.WebAuthn.PasswordlessDev.Models.ServerAuthenticatorAssertionResponse;
import com.WebAuthn.PasswordlessDev.Models.ServerAuthenticatorAttestationResponse;
import com.WebAuthn.PasswordlessDev.Models.ServerPublicKeyCredentialCreationOptionsRequest;
import com.WebAuthn.PasswordlessDev.Models.ServerPublicKeyCredentialGetOptionsRequest;
import com.WebAuthn.PasswordlessDev.Models.TokenDTO;
import com.WebAuthn.PasswordlessDev.Services.PasswordlessDevService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

@RestController
@CrossOrigin
public class WebAuthnController {

    private final PasswordlessDevService passwordlessDevService;
    private String session;

    @Autowired
    public WebAuthnController(PasswordlessDevService passwordlessDevService) {
        this.passwordlessDevService = passwordlessDevService;
    }

    // Start Registration
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/attestation/options", produces = "application/json")
    public String createOptions(
            @RequestBody ServerPublicKeyCredentialCreationOptionsRequest req) {
        try {
            TokenDTO token = passwordlessDevService.retrieveRegistrationToken(req).block();
            RegBeginPayload beginPayload = new RegBeginPayload(token.getToken(), "localhost", "http://localhost");
            String jsonData = passwordlessDevService.retrieveRegOptions(beginPayload).block();
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(jsonData);
            JsonNode dataNode = jsonNode.get("data");
            JsonNode sessionNode = jsonNode.get("session");
            session = sessionNode.asText();
            // customize response to fit FIDO conformance test tool
            ObjectNode objectNode = (ObjectNode) dataNode;
            objectNode.put("errorMessage", "");
            objectNode.put("status", "ok");
            return mapper.writeValueAsString(objectNode);
        } catch (WebClientResponseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    // Complete Registration
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/attestation/result", produces = "application/json")
    public ResponseEntity completeRegistration(
            @RequestBody ServerAuthenticatorAttestationResponse resp) {
        try {
            RegCompletePayload completePayload = new RegCompletePayload(resp, "localhost",
                    "http://localhost", session, "test");
            String jsonData = passwordlessDevService.completeRegistration(completePayload).block();
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(jsonData);
            JsonNode dataNode = jsonNode.get("data");
            ObjectNode responseBody = new ObjectMapper().createObjectNode();
            responseBody.put("status", "ok");
            responseBody.put("errorMessage", "");
            return new ResponseEntity<>(responseBody.toString(), HttpStatus.CREATED);
        } catch (WebClientResponseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    // Start Login
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/assertion/options", produces = "application/json")
    public String getLoginOptions(
            @RequestBody ServerPublicKeyCredentialGetOptionsRequest req) {
        try {
            if (req.getUsername().isEmpty()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username is required");
            }
            LoginBeginPayload beginPayload = new LoginBeginPayload(
                    "http://localhost",
                    req.getUserId(),
                    req.getUserVerification(),
                    "localhost");
            String jsonData = passwordlessDevService.retrieveLoginOptions(beginPayload).block();
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(jsonData);
            JsonNode dataNode = jsonNode.get("data");
            JsonNode sessionNode = jsonNode.get("session");
            session = sessionNode.asText();
            // customize response to fit FIDO conformance test tool
            ObjectNode objectNode = (ObjectNode) dataNode;
            objectNode.put("errorMessage", "");
            objectNode.put("status", "ok");
            return mapper.writeValueAsString(objectNode);
        } catch (WebClientResponseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    // Complete Login
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/assertion/result", produces = "application/json")
    public ResponseEntity completeLogin(
            @RequestBody ServerAuthenticatorAssertionResponse req) {
        try {
            LoginCompletePayload completePayload = new LoginCompletePayload(
                    req,
                    session,
                    "http://localhost",
                    "localhost");
            String jsonData = passwordlessDevService.completeLogin(completePayload).block();
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(jsonData);
            String verifyToken = jsonNode.get("token").asText();
            String verifyResponse = passwordlessDevService.validateToken(new TokenDTO(verifyToken))
                    .block();
            jsonNode = mapper.readTree(verifyResponse);
            if (jsonNode.get("success").asBoolean()) {
                ObjectNode responseBody = new ObjectMapper().createObjectNode();
                responseBody.put("status", "ok");
                responseBody.put("errorMessage", "");
                return new ResponseEntity<>(responseBody.toString(), HttpStatus.CREATED);
            } else {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Login not successful");
            }
        } catch (WebClientResponseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }
}
