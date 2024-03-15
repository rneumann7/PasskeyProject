package com.WebAuthn.Yubico.Controller;

import com.WebAuthn.Yubico.Model.AuthenticatorModel;
import com.WebAuthn.Yubico.Model.ServerAuthenticatorAssertionResponse;
import com.WebAuthn.Yubico.Model.ServerPublicKeyCredentialGetOptionsRequest;
import com.WebAuthn.Yubico.Model.UserModel;
import com.WebAuthn.Yubico.Service.CredentialAccessService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.*;
import com.yubico.webauthn.StartAssertionOptions.StartAssertionOptionsBuilder;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.Optional;

@RestController
@RequestMapping("/assertion")
@CrossOrigin
public class AuthenticationController {

    private CredentialAccessService accessService;
    private RelyingParty rp;
    private AssertionRequest assertionRequest;

    @Autowired
    public AuthenticationController(CredentialAccessService accessService, RelyingParty rp) {
        this.accessService = accessService;
        this.rp = rp;
        this.assertionRequest = null;
    }

    /**
     * Builds and returns assertion options
     * 
     * @param req get options request
     * @return
     */
    @ResponseStatus(HttpStatus.OK)
    @PostMapping(value = "/options", produces = "application/json")
    public String startAuthentication(
            @RequestBody ServerPublicKeyCredentialGetOptionsRequest req) {

        UserModel user = new UserModel(req.getUsername());
        UserModel existingUser = accessService.getUserRepo().findByUsername(user.getUsername());
        AssertionRequest request;
        StartAssertionOptionsBuilder optionsBuilder = StartAssertionOptions.builder();
        if (req.getUserVerification().equals("required"))
            optionsBuilder.userVerification(UserVerificationRequirement.REQUIRED);
        if (existingUser != null) {
            request = rp.startAssertion(optionsBuilder
                    .username(existingUser.getUsername())
                    .build());
        } else {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Authentication failed, user does not exist. For sign in with discoverable, set username to an empty string.");
        }
        try {
            this.assertionRequest = request;
            return request.toCredentialsGetJson();
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    /**
     * Finishes authentication
     * 
     * @param resp assertion response
     * @return
     */
    @PostMapping(value = "/result", produces = "application/json")
    public ResponseEntity finishAuthentication(
            @RequestBody ServerAuthenticatorAssertionResponse resp) {
        try {
            AssertionRequest request = this.assertionRequest;
            ObjectMapper mapper = new ObjectMapper();
            if (request != null) {
                String respJson = mapper.writeValueAsString(resp);
                PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc;
                pkc = PublicKeyCredential.parseAssertionResponseJson(respJson);
                AssertionResult result = rp.finishAssertion(FinishAssertionOptions.builder()
                        .request(request)
                        .response(pkc)
                        .build());
                if (result.isSuccess()) {
                    // update usage count
                    Optional<AuthenticatorModel> currentAuth = accessService.getAuthRepo()
                            .findByCredentialId(result.getCredential().getCredentialId());
                    if (currentAuth.isPresent()) {
                        AuthenticatorModel auth = currentAuth.get();
                        auth.setUsageCount(result.getSignatureCount());
                        accessService.getAuthRepo().save(auth);
                    }
                    ObjectNode responseBody = new ObjectMapper().createObjectNode();
                    responseBody.put("status", "ok");
                    responseBody.put("errorMessage", "");
                    return new ResponseEntity<>(responseBody.toString(), HttpStatus.CREATED);
                } else {
                    ObjectNode responseBody = new ObjectMapper().createObjectNode();
                    responseBody.put("status", "failed");
                    responseBody.put("errorMessage", "No Success");
                    return new ResponseEntity<>(responseBody.toString(), HttpStatus.CREATED);
                }
            } else {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Authentication failed, AssertionRequest is null");
            }
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage(), e);
        } catch (AssertionFailedException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage(), e);
        }
    }
}
