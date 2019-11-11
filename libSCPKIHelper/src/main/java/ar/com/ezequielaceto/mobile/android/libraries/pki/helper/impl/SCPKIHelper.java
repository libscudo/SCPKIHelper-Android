package ar.com.ezequielaceto.mobile.android.libraries.pki.helper.impl;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.util.Base64;

import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static android.security.keystore.KeyProperties.PURPOSE_ENCRYPT;
import static android.security.keystore.KeyProperties.PURPOSE_DECRYPT;
import static android.security.keystore.KeyProperties.PURPOSE_VERIFY;
import static android.security.keystore.KeyProperties.PURPOSE_SIGN;

public final class SCPKIHelper {

    public static SCPKIHelper sharedImpl;

    private String serviceName;

    public static synchronized SCPKIHelper shared(Context context) {
        if (sharedImpl == null) {
            sharedImpl = new SCPKIHelper(context.getPackageName());
        }
        return sharedImpl;
    }

    public SCPKIHelper(String serviceName) {
        this.serviceName = serviceName;
    }

    public KeyPair generateKeyPair(SCPKIKeySpec specs, String identifier) throws Exception {

        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(specs.getKeyType(), specs.getProvider());
            kpg.initialize(new KeyGenParameterSpec.Builder(
                    aliasFor(identifier),
                    PURPOSE_SIGN | PURPOSE_VERIFY | PURPOSE_DECRYPT | PURPOSE_ENCRYPT)
                    .setDigests(specs.getDigest(), specs.getDigest())
                    .setKeySize(specs.getSizeInBits())
                    .setEncryptionPaddings(specs.getEncryptionPadding(), specs.getEncryptionPadding())
                    .setSignaturePaddings(specs.getSignaturePadding(), specs.getSignaturePadding())
                    .setUserAuthenticationRequired(specs.requireUserAuthentication())
                    .setUserAuthenticationValidityDurationSeconds(specs.getReuseAuthenticationDuration())
                    .build());

            KeyPair keyPair = kpg.generateKeyPair();

            return keyPair;
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            String causeMessage = e.getCause().getMessage().toLowerCase();
            if (causeMessage.contains("secure") && causeMessage.contains("lock") && causeMessage.contains("screen")) {
                throw new AuthenticationRequiredException(e);
            }
            throw new AlgorithmException(e);
        } catch (NoSuchProviderException e) {
            throw new KeyStoreException(e);
        } catch (Exception e) {
            throw e;
        }
    }

    public PublicKey getPublicKey(SCPKIKeySpec specs, String identifier) throws KeyStoreException, AlgorithmException, KeyNotFoundForIdentifier {
        try {
            KeyStore keyStore = KeyStore.getInstance(specs.getProvider());
            keyStore.load(null);

            Certificate certificate = keyStore.getCertificate(aliasFor(identifier));
            if (certificate != null) {
                return certificate.getPublicKey();
            }
        } catch (CertificateException | IOException | NoSuchAlgorithmException | java.security.KeyStoreException e) {
            if (e instanceof NoSuchAlgorithmException) {
                throw new AlgorithmException(e);
            }
            throw new KeyStoreException(e);
        }
        throw new KeyNotFoundForIdentifier();
    }

    public PrivateKey getPrivateKey(SCPKIKeySpec specs, String identifier) throws KeyStoreException, AlgorithmException, KeyNotFoundForIdentifier {
        try {
            KeyStore keyStore = KeyStore.getInstance(specs.getProvider());
            keyStore.load(null);

            KeyStore.Entry entry = keyStore.getEntry(aliasFor(identifier), null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                throw new KeyNotFoundForIdentifier();
            }
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
            return privateKeyEntry.getPrivateKey();

        } catch (CertificateException | IOException | NoSuchAlgorithmException | java.security.KeyStoreException e) {
            if (e instanceof NoSuchAlgorithmException) {
                throw new AlgorithmException(e);
            }
            throw new KeyStoreException(e);
        } catch (UnrecoverableEntryException e) {
            throw new KeyNotFoundForIdentifier();
        }
    }

    public Certificate getCertificate(SCPKIKeySpec specs, String identifier) throws KeyStoreException {
        try {
            KeyStore keyStore = KeyStore.getInstance(specs.getProvider());
            keyStore.load(null);

            Certificate certificate = keyStore.getCertificate(aliasFor(identifier));
            return certificate;
        } catch (CertificateException | IOException | NoSuchAlgorithmException | java.security.KeyStoreException e) {
            throw new KeyStoreException(e);
        }
    }

    public Certificate importCertificate(SCPKIKeySpec specs, String identifier, String pem) throws KeyStoreException {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");

            KeyStore keyStore = KeyStore.getInstance(specs.getProvider());
            keyStore.load(null);


            String der = pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "");
            final byte[] bytes = Base64.decode(der, Base64.DEFAULT);
            X509Certificate certificate = (X509Certificate)factory.generateCertificate(new ByteArrayInputStream(bytes));

            keyStore.setCertificateEntry(aliasFor(identifier), certificate);

            return certificate;
        } catch (CertificateException | IOException | NoSuchAlgorithmException | java.security.KeyStoreException e) {
            throw new KeyStoreException(e);
        }
    }

    @NotNull
    private String aliasFor(String identifier) {
        return serviceName + "." + identifier;
    }


    public class AlgorithmException extends Exception {
        AlgorithmException(Throwable t) {
            super(t);
        }
    }

    public class AuthenticationRequiredException extends Exception {
        AuthenticationRequiredException(Throwable t) {
            super(t);
        }
    }

    public class KeyStoreException extends Exception {
        KeyStoreException(Throwable t) {
            super(t);
        }
    }

    public class KeyNotFoundForIdentifier extends Exception {
        KeyNotFoundForIdentifier() {
            super();
        }
        KeyNotFoundForIdentifier(Throwable t) {
            super(t);
        }
    }

}
