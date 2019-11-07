package ar.com.ezequielaceto.mobile.android.libraries.pki;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;

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
                    serviceName + "." + identifier,
                    PURPOSE_SIGN | PURPOSE_VERIFY | PURPOSE_DECRYPT | PURPOSE_ENCRYPT)
                    .setDigests(specs.getDigest(), specs.getDigest())
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
            throw new AlgorithmException(e.getMessage());
        } catch (NoSuchProviderException e) {
            throw new KeyStoreException(e);
        } catch (Exception e) {
            throw e;
        }
    }

    public PublicKey getPublicKey(SCPKIKeySpec specs, String identifier) {
        return null;
    }


    public class AlgorithmException extends Exception {
        AlgorithmException(String message) {
            super(message);
        }
    }

    public class AuthenticationRequiredException extends Exception {
        AuthenticationRequiredException(Throwable t) {
            super(t);
        }
    }

}
