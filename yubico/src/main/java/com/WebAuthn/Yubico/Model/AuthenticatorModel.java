package com.WebAuthn.Yubico.Model;

import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.ByteArray;
import jakarta.persistence.*;

@Entity
public class AuthenticatorModel {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @Column
    private String name;
    @Lob
    @Column(nullable = false, columnDefinition = "BLOB")
    private ByteArray publicKey;
    @Lob
    @Column(nullable = false, columnDefinition = "BLOB")
    private ByteArray credentialId;
    @Column(nullable = false)
    private Long usageCount;
    @ManyToOne
    private UserModel user;

    public Long getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public ByteArray getPublicKey() {
        return publicKey;
    }

    public ByteArray getCredentialId() {
        return credentialId;
    }

    public Long getUsageCount() {
        return usageCount;
    }

    public void setUsageCount(Long usageCount) {
        this.usageCount = usageCount;
    }

    public UserModel getUser() {
        return user;
    }

    public AuthenticatorModel(String name, UserModel user, RegistrationResult result) {
        this.name = name;
        this.user = user;
        this.publicKey = result.getPublicKeyCose();
        this.credentialId = result.getKeyId().getId();
        this.usageCount = result.getSignatureCount();
    }

    public AuthenticatorModel() {
    }
}
