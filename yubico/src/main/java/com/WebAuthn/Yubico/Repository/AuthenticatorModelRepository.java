package com.WebAuthn.Yubico.Repository;

import com.WebAuthn.Yubico.Model.AuthenticatorModel;
import com.WebAuthn.Yubico.Model.UserModel;
import com.yubico.webauthn.data.ByteArray;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuthenticatorModelRepository extends CrudRepository<AuthenticatorModel, Long> {

    List<AuthenticatorModel> findAllByUser(UserModel user);

    Optional<AuthenticatorModel> findByCredentialId(ByteArray credentialId);

    List<AuthenticatorModel> findAllByCredentialId(ByteArray credentialId);
}
