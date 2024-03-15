package com.WebAuthn.Yubico.Utility;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import com.yubico.webauthn.attestation.AttestationTrustSource;
import com.yubico.webauthn.data.ByteArray;

public class CustomAttestationTrustSource implements AttestationTrustSource {

    private X509Certificate certificate;
    private CertificateFactory cf;
    private PKIXParameters params;

    public CustomAttestationTrustSource() {
        // Load the root certificate
        try (InputStream inStream = getClass().getResourceAsStream("/trustedCert.pem")) {
            this.cf = CertificateFactory.getInstance("X.509");
            this.certificate = (X509Certificate) cf.generateCertificate(inStream);
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
        }
        // Set the trust anchor and parameters
        try {
            TrustAnchor anchor = new TrustAnchor(this.certificate, null);
            this.params = new PKIXParameters(Collections.singleton(anchor));
            params.setRevocationEnabled(false); // Disable CRL checks (this is optional)
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }

    @Override
    public TrustRootsResult findTrustRoots(List<X509Certificate> attestationCertificateChain,
            Optional<ByteArray> aaguid) {
        // Create the validator and validate the certificate chain
        try {
            CertPathValidator validator = CertPathValidator.getInstance(CertPathValidator.getDefaultType());
            CertPath certPath = this.cf.generateCertPath(attestationCertificateChain);
            validator.validate(certPath, params);
            // If the chain is invalid, return an empty set
        } catch (Exception e) {
            return TrustRootsResult.builder()
                    .trustRoots(new HashSet<>())
                    .build();
        }
        return TrustRootsResult.builder()
                .trustRoots(new HashSet<>(Collections.singletonList(this.certificate)))
                .enableRevocationChecking(false)
                .build();
    }

}
