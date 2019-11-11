package ar.com.ezequielaceto.mobile.android.libraries.pki.helper.impl;

import android.security.keystore.KeyProperties;

import java.security.SecureRandom;

public class SCPKIKeySpec {

    private static final String AndroidKeyStoreProvider = "AndroidKeyStore";
    private static SecureRandom secureRandom = new SecureRandom();

    public static final SCPKIKeySpec common = new SCPKIKeySpec(KeyProperties.KEY_ALGORITHM_RSA,
            AndroidKeyStoreProvider,
            2048,
            KeyProperties.SIGNATURE_PADDING_RSA_PKCS1,
            KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1,
            KeyProperties.DIGEST_SHA256);

    private String keyType, provider, signaturePadding, encryptionPadding, digest;
    private int sizeInBits;
    private boolean requireUserAuthentication;
    private int reuseAuthenticationDuration;

    public SCPKIKeySpec(String keyType, String provider, int sizeInBits, String signaturePadding, String encryptionPadding, String digest) {
        this.keyType = keyType;
        this.provider = provider;
        this.sizeInBits = sizeInBits;
        this.signaturePadding = signaturePadding;
        this.encryptionPadding = encryptionPadding;
        this.digest = digest;
        this.requireUserAuthentication = true;
        this.reuseAuthenticationDuration = 30;
    }

    public String getKeyType() {
        return keyType;
    }

    public String getProvider() {
        return provider;
    }

    public String getSignaturePadding() {
        return signaturePadding;
    }

    public String getEncryptionPadding() {
        return encryptionPadding;
    }

    public String getDigest() {
        return digest;
    }

    public int getSizeInBits() {
        return sizeInBits;
    }

    public boolean requireUserAuthentication() {
        return requireUserAuthentication;
    }

    public void setRequireUserAuthentication(boolean requireUserAuthentication) {
        this.requireUserAuthentication = requireUserAuthentication;
    }

    public int getReuseAuthenticationDuration() {
        return reuseAuthenticationDuration;
    }

    public void setReuseAuthenticationDuration(int reuseAuthenticationDuration) {
        this.reuseAuthenticationDuration = reuseAuthenticationDuration;
    }
}
