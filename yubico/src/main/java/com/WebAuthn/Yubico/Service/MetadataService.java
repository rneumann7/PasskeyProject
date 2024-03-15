package com.WebAuthn.Yubico.Service;

import com.yubico.fido.metadata.FidoMetadataDownloader;
import com.yubico.fido.metadata.FidoMetadataService;

import java.io.File;
import java.security.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

//@Service
public class MetadataService {

    FidoMetadataDownloader downloader;
    FidoMetadataService mds;

    @Autowired
    public MetadataService() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            SignatureException, InvalidKeyException {
        try {
            downloader = FidoMetadataDownloader.builder()
                    .expectLegalHeader(
                            "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/")
                    .useDefaultTrustRoot()
                    .useTrustRootCacheFile(new File("./fido-mds-trust-root"))
                    .useDefaultBlob()
                    .useBlobCacheFile(new File("./fido-mds-blob"))
                    .verifyDownloadsOnly(true) // Recommended, otherwise cache may expire if BLOB certificate expires
                    // See: https://github.com/Yubico/java-webauthn-server/issues/294
                    .build();

            mds = FidoMetadataService.builder()
                    .useBlob(downloader.loadCachedBlob())
                    .build();
            System.out.println("done");
        } catch (Exception e) {
            throw new RuntimeException("Metadataservice can not be build.");
        }
    }

    public FidoMetadataService getMds() {
        return this.mds;
    }
}