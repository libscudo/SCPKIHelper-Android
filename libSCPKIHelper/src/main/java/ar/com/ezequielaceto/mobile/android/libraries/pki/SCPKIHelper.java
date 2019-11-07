package ar.com.ezequielaceto.mobile.android.libraries.pki;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(specs.getKeyType(), specs.getProvider());
        kpg.initialize(new KeyGenParameterSpec.Builder(
                serviceName + "." + identifier,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(specs.getDigest(), specs.getDigest())
                .setEncryptionPaddings(specs.getPadding(), specs.getPadding())
                .setUserAuthenticationRequired(specs.requireUserAuthentication())
                .setUserAuthenticationValidityDurationSeconds(specs.getReuseAuthenticationDuration())
                .build());

        KeyPair keyPair = kpg.generateKeyPair();

        return keyPair;
    }

}
