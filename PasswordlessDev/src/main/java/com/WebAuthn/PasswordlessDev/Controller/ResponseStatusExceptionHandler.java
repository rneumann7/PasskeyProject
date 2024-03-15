package com.WebAuthn.PasswordlessDev.Controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * This class handles exceptions thrown by the controller and returns a
 * json.path
 * This is used to get the specific error response form that is needed by the
 * FIDO conformance test tool
 */
@ControllerAdvice
public class ResponseStatusExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<String> handleResponseStatusException(ResponseStatusException ex) {
        // Create a JSON object to send as the response body
        ObjectNode responseBody = new ObjectMapper().createObjectNode();
        responseBody.put("status", "error");
        responseBody.put("errorMessage", ex.getMessage());

        // Return a ResponseEntity with the status from the exception and the JSON as
        // the body
        return new ResponseEntity<>(responseBody.toString(), HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
