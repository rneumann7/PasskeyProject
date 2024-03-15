package com.WebAuthn.Yubico.Controller;

import com.WebAuthn.Yubico.Model.*;
import com.WebAuthn.Yubico.Service.CredentialAccessService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria.AuthenticatorSelectionCriteriaBuilder;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@RestController
@RequestMapping("/attestation")
@CrossOrigin
public class RegistrationController {

    private CredentialAccessService accessService;
    private RelyingParty rp;
    private PublicKeyCredentialCreationOptions tempPKOptions;

    @Autowired
    public RegistrationController(CredentialAccessService accessService, RelyingParty rp) {
        this.accessService = accessService;
        this.rp = rp;
        this.tempPKOptions = null;
    }

    /**
     * Creates new user, builds and returns registration options
     * 
     * @param req registration request
     * @return
     */
    @ResponseStatus(HttpStatus.OK)
    @PostMapping(value = "/options", produces = "application/json")
    public String startRegisterNewAuthenticator(
            @RequestBody ServerPublicKeyCredentialCreationOptionsRequest req) {
        // if username is empty, return error
        if (req.getUsername().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Username cannot be empty.");
        }
        // check if user exists, if not, create new user
        UserModel user = new UserModel(req.getUsername(), req.getDisplayName(), req.getUserId());
        UserModel existingUser = accessService.getUserRepo().findByUsername(user.getUsername());
        if (existingUser == null) {
            accessService.getUserRepo().save(user);
        }
        UserIdentity userIdentity = user.toUserIdentity();
        // set up authenticator selection criteria
        AuthenticatorSelectionCriteriaBuilder authSelectionBuilder = AuthenticatorSelectionCriteria.builder();
        try {
            authSelectionBuilder
                    .userVerification(UserVerificationRequirement.valueOf(req.getUserVerification().toUpperCase()));
            authSelectionBuilder.residentKey(ResidentKeyRequirement.valueOf(req.getRkOption().toUpperCase()));
        } catch (Exception e) {
        }
        // build options
        StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                .user(userIdentity)
                .authenticatorSelection(authSelectionBuilder.build())
                .build();
        PublicKeyCredentialCreationOptions registration = rp.startRegistration(registrationOptions);
        this.tempPKOptions = registration;
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(registration.toCredentialsCreateJson());
            JsonNode publicKeyJson = jsonNode.get("publicKey");
            // Convert JsonNode to ObjectNode
            ObjectNode objectNode = (ObjectNode) publicKeyJson;
            objectNode.put("errorMessage", "");
            objectNode.put("status", "ok");
            ObjectNode authSelection = (ObjectNode) objectNode.get("authenticatorSelection");
            // set requireResidentKey
            try {
                authSelection.put("requireResidentKey", req.isDiscoverable());
            } catch (Exception e) {
            }
            return mapper.writeValueAsString(objectNode);
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error processing JSON.", e);
        }
    }

    /**
     * Finishes registration process and saves new authenticator
     * 
     * @param resp registration response
     * @return
     */
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping(value = "/result", produces = "application/json")
    public ResponseEntity finishRegisterNewAuthenticator(
            @RequestBody ServerAuthenticatorAttestationResponse resp) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            PublicKeyCredentialCreationOptions requestOptions = this.tempPKOptions;
            if (requestOptions != null) {
                String respJson = mapper.writeValueAsString(resp);
                PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc = PublicKeyCredential
                        .parseRegistrationResponseJson(respJson);
                FinishRegistrationOptions options = FinishRegistrationOptions.builder()
                        .request(requestOptions)
                        .response(pkc)
                        .build();
                RegistrationResult result = rp.finishRegistration(options);
                // check for trust if not none or self type
                if (result.getAttestationType() != AttestationType.NONE
                        && result.getAttestationType() != AttestationType.SELF_ATTESTATION) {
                    if (!result.isAttestationTrusted()) {
                        throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                                "Attestation not trusted. Try to register again!");
                    }
                }
                UserModel owningUser = accessService.getUserRepo().findByUsername(requestOptions.getUser().getName());
                AuthenticatorModel savedAuth = new AuthenticatorModel("Testname",
                        owningUser,
                        result);
                accessService.getAuthRepo().save(savedAuth);
                ObjectNode responseBody = new ObjectMapper().createObjectNode();
                responseBody.put("status", "ok");
                responseBody.put("errorMessage", "");
                return new ResponseEntity<>(responseBody.toString(), HttpStatus.CREATED);
            } else {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Cached request expired. Try to register again!");
            }
        } catch (RegistrationFailedException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage(), e);
        }
    }
}
