package com.WebAuthn.Yubico.Service;

import com.WebAuthn.Yubico.Model.AuthenticatorModel;
import com.WebAuthn.Yubico.Model.UserModel;
import com.WebAuthn.Yubico.Repository.AuthenticatorModelRepository;
import com.WebAuthn.Yubico.Repository.UserModelRepository;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Repository
public class CredentialAccessService implements CredentialRepository {

    private AuthenticatorModelRepository authRepo;
    private UserModelRepository userRepo;

    @Autowired
    public CredentialAccessService(AuthenticatorModelRepository authRepo, UserModelRepository userRepo) {
        this.authRepo = authRepo;
        this.userRepo = userRepo;
    }

    public AuthenticatorModelRepository getAuthRepo() {
        return authRepo;
    }

    public UserModelRepository getUserRepo() {
        return userRepo;
    }

    // The following methods are required by the CredentialRepository interface of
    // the yubico library.
    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        UserModel user = userRepo.findByUsername(username);
        List<AuthenticatorModel> auth = authRepo.findAllByUser(user);
        return auth.stream()
                .map(
                        authenticator -> PublicKeyCredentialDescriptor.builder()
                                .id(authenticator.getCredentialId())
                                .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        UserModel user = userRepo.findByHandle(userHandle);
        if (user == null) {
            return Optional.empty();
        }
        return Optional.of(user.getUsername());
    }

    @Override

    public Optional<ByteArray> getUserHandleForUsername(String username) {
        UserModel user = userRepo.findByUsername(username);
        return Optional.of(user.getHandle());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Optional<AuthenticatorModel> auth = authRepo.findByCredentialId(credentialId);
        return auth.map(
                authenticator -> RegisteredCredential.builder()
                        .credentialId(authenticator.getCredentialId())
                        .userHandle(authenticator.getUser().getHandle())
                        .publicKeyCose(authenticator.getPublicKey())
                        .signatureCount(authenticator.getUsageCount())
                        .build());
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        List<AuthenticatorModel> auth = authRepo.findAllByCredentialId(credentialId);
        return auth.stream()
                .map(
                        authenticator -> RegisteredCredential.builder()
                                .credentialId(authenticator.getCredentialId())
                                .userHandle(authenticator.getUser().getHandle())
                                .publicKeyCose(authenticator.getPublicKey())
                                .signatureCount(authenticator.getUsageCount())
                                .build())
                .collect(Collectors.toSet());
    }

}
