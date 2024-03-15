package com.WebAuthn.Yubico.Model;

import com.WebAuthn.Yubico.Utility.UUIDGenerator;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import jakarta.persistence.*;

@Entity
public class UserModel {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;
    @Column(nullable = false, unique = true)
    private String username;
    @Lob
    @Column(nullable = false, columnDefinition = "BLOB", length = 64)
    private ByteArray handle;
    private String displayName;

    public UserModel(String username, String displayName, ByteArray handle) {
        this.username = username;
        this.handle = handle;
        this.displayName = displayName;
    }

    public UserModel(String username) {
        this.username = username;
        this.handle = UUIDGenerator.generateUUIDByteArray();
    }

    public UserModel() {
    };

    public String getUsername() {
        return username;
    }

    public ByteArray getHandle() {
        return handle;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setHandle(ByteArray handle) {
        this.handle = handle;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public UserIdentity toUserIdentity() {
        return UserIdentity.builder()
                .name(getUsername())
                .displayName(getDisplayName())
                .id(getHandle())
                .build();
    }

}
