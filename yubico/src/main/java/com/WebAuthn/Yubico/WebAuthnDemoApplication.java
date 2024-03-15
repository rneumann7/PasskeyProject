package com.WebAuthn.Yubico;

import com.WebAuthn.Yubico.Service.CredentialAccessService;
import com.WebAuthn.Yubico.Utility.CustomAttestationTrustSource;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.Collections;

@SpringBootApplication
public class WebAuthnDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(WebAuthnDemoApplication.class, args);
	}

	@Bean
	@Autowired
	public RelyingParty relyingParty(CredentialAccessService registrationRepository) {
		RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
				.id("localhost")
				.name("localhost")
				.build();
		// set trust source
		CustomAttestationTrustSource cats = new CustomAttestationTrustSource();
		return RelyingParty.builder()
				.identity(rpIdentity)
				.credentialRepository(registrationRepository)
				.attestationTrustSource(cats)
				.origins(Collections.singleton("http://localhost:8080"))
				.build();
	}

}
