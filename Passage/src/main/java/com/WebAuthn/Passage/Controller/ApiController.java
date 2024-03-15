package com.WebAuthn.Passage.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;

import com.WebAuthn.Passage.Models.FinishLoginPayload;
import com.WebAuthn.Passage.Models.FinishRegisterPayload;
import com.WebAuthn.Passage.Models.ServerAuthenticatorAssertionResponse;
import com.WebAuthn.Passage.Models.ServerAuthenticatorAttestationResponse;
import com.WebAuthn.Passage.Models.ServerPublicKeyCredentialCreationOptionsRequest;
import com.WebAuthn.Passage.Models.ServerPublicKeyCredentialGetOptionsRequest;
import com.WebAuthn.Passage.Models.StartPayload;
import com.WebAuthn.Passage.Services.PassageService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

@RestController
@CrossOrigin
public class ApiController {

    private final PassageService passageService;
    private String handshakeId;
    private String userID;

    @Autowired
    public ApiController(PassageService passageService) {
        this.passageService = passageService;
    }

    /**
     * Creates the options for the registration
     * 
     * @param req the request from the client
     * @return
     */
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/attestation/options", produces = "application/json")
    public String getAttOptions(
            @RequestBody ServerPublicKeyCredentialCreationOptionsRequest req) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            StartPayload payload = new StartPayload(req.getUsername());
            String startResponse = passageService.retrieveRegistrationOptions(payload).block();
            JsonNode responseNode = mapper.readTree(startResponse);
            userID = responseNode.get("user").get("id").asText();
            JsonNode handshakeNode = responseNode.get("handshake");
            handshakeId = handshakeNode.get("id").asText();
            JsonNode optionsNode = handshakeNode.get("challenge").get("publicKey");
            // customize response to fit FIDO conformance test tool
            ObjectNode objectNode = (ObjectNode) optionsNode;
            objectNode.put("errorMessage", "");
            objectNode.put("status", "ok");
            return mapper.writeValueAsString(objectNode);
        } catch (WebClientResponseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    /**
     * Completes the registration
     * 
     * @param resp the response from the client
     * @return
     */
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/attestation/result", produces = "application/json")
    public ResponseEntity completeRegistration(
            @RequestBody ServerAuthenticatorAttestationResponse resp) {
        try {
            FinishRegisterPayload payload = new FinishRegisterPayload(handshakeId, resp, userID);
            String jsonData = passageService.finishRegistration(payload).block();
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

    /**
     * Creates the options for the login
     * 
     * @param req the request from the client
     * @return
     */
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/assertion/options", produces = "application/json")
    public String getAssOptions(
            @RequestBody ServerPublicKeyCredentialGetOptionsRequest req) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            if (req.getUsername().isEmpty()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username cannot be empty.");
            }
            StartPayload payload = new StartPayload(req.getUsername());
            String startResponse = passageService.retrieveLoginOptions(payload).block();
            JsonNode responseNode = mapper.readTree(startResponse);
            userID = responseNode.get("user").get("id").asText();
            JsonNode handshakeNode = responseNode.get("handshake");
            handshakeId = handshakeNode.get("id").asText();
            JsonNode optionsNode = handshakeNode.get("challenge").get("publicKey");
            // customize response to fit FIDO conformance test tool
            ObjectNode objectNode = (ObjectNode) optionsNode;
            objectNode.put("errorMessage", "");
            objectNode.put("status", "ok");
            return mapper.writeValueAsString(objectNode);
        } catch (WebClientResponseException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getResponseBodyAsString(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        }
    }

    /**
     * Completes the login
     * 
     * @param resp the response from the client
     * @return
     */
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/assertion/result", produces = "application/json")
    public ResponseEntity completeLogin(
            @RequestBody ServerAuthenticatorAssertionResponse resp) {
        try {
            FinishLoginPayload payload = new FinishLoginPayload(handshakeId, resp, userID);
            String jsonData = passageService.finishLogin(payload).block();
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

}
