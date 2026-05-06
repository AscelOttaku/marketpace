package com.security.helper.security;

import com.security.helper.common.MessageSourceHelper;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Value;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class EncryptData {

    MessageSourceHelper messageSourceHelper;

    @NonFinal
    @Value("${token.signing.secret.key}")
    String SECRET_KEY;

    @NonFinal
    @Value("${private.key.path}")
    String privateKeyPath;

    @NonFinal
    @Value("${public.key.path}")
    String publicLeyPath;

    @NonFinal
    PublicKey publicKey;
    @NonFinal
    PrivateKey privateKey;

    public Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public SignatureAlgorithm getSignature() {
        return SignatureAlgorithm.HS256;
    }

    @PostConstruct
    public void init() {
        initPublicKey();
        initPrivateKey();
    }

    public String encrypt(String payload) {
        var jwe = new JsonWebEncryption();
        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
        jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512);
        jwe.setKey(publicKey);
        jwe.setPayload(payload);
        try {
            return jwe.getCompactSerialization();
        } catch (JoseException e) {
            log.error(e.getMessage(), e);
            return "invalid data";
        }
    }

    public String decrypt(String jwe) {
        try {
            var jweObject = new JsonWebEncryption();
            jweObject.setCompactSerialization(jwe);
            jweObject.setKey(privateKey);
            return jweObject.getPlaintextString();
        } catch (JoseException e) {
            log.error(e.getMessage(), e);
            return "invalid data";
        }
    }

    private void initPublicKey() {
        try (var inputStream = getClass().getClassLoader().getResourceAsStream(publicLeyPath)) {
            var key = new String(inputStream.readAllBytes(), Charset.defaultCharset());
            var publicKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");
            var decodedBytes = Base64.decodeBase64(publicKeyPEM);
            var keyFactory = KeyFactory.getInstance("RSA");
            var keySpec = new X509EncodedKeySpec(decodedBytes);
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (IOException e) {
            log.error(messageSourceHelper.get("public.key.read.error", e.getMessage()));
        } catch (Exception e) {
            log.error(messageSourceHelper.get("public.key.generate.error", e.getMessage()));
        }
    }

    private void initPrivateKey() {
        try (var inputStream = getClass().getClassLoader().getResourceAsStream(privateKeyPath)) {
            var key = new String(inputStream.readAllBytes(), Charset.defaultCharset());
            var privateKeyPEM = key.replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END RSA PRIVATE KEY-----", "");
            var decodedBytes = Base64.decodeBase64(privateKeyPEM);
            Security.addProvider(new BouncyCastleProvider());
            var keyFactory = KeyFactory.getInstance("RSA");
            var keySpec = new PKCS8EncodedKeySpec(decodedBytes);
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (IOException e) {
            log.error(messageSourceHelper.get("private.key.read.error", e.getMessage()));
        } catch (Exception e) {
            log.error(messageSourceHelper.get("private.key.generate.error", e.getMessage()));
        }
    }
}
