package com.WebAuthn.Yubico.Repository;

import com.WebAuthn.Yubico.Model.UserModel;
import com.yubico.webauthn.data.ByteArray;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserModelRepository extends CrudRepository<UserModel, Long> {

    UserModel findByUsername(String username);

    UserModel findByHandle(ByteArray handle);

}
