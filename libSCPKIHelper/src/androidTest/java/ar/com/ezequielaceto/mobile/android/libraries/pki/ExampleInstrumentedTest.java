package ar.com.ezequielaceto.mobile.android.libraries.pki;

import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void generateKeyPairOk() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        try {
            SCPKIKeySpec specs  = SCPKIKeySpec.common;
            specs.setRequireUserAuthentication(false);

            KeyPair keyPair = SCPKIHelper.shared(appContext).generateKeyPair(specs, "test_keys");
            assertTrue(keyPair != null && keyPair.getPrivate() != null && keyPair.getPublic() != null);
            return;
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertTrue(false);
    }

    @Test
    public void generateKeyPairFailWithNoAuth() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        try {
            SCPKIKeySpec specs  = SCPKIKeySpec.common;
            specs.setRequireUserAuthentication(true);

            SCPKIHelper.shared(appContext).generateKeyPair(specs, "test_keys");
        } catch (Exception e) {
            assertTrue(e instanceof SCPKIHelper.AuthenticationRequiredException);
            return;
        }
        assertTrue(false);
    }

    @Test
    public void getPublicKey() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        try {
            SCPKIKeySpec specs  = SCPKIKeySpec.common;
            specs.setRequireUserAuthentication(false);

            PublicKey publicKey = SCPKIHelper.shared(appContext).getPublicKey(specs, "test_keys");
            assertTrue(publicKey != null);
            return;
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertTrue(false);
    }

    @Test
    public void getPrivateKey() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        try {
            SCPKIKeySpec specs  = SCPKIKeySpec.common;
            specs.setRequireUserAuthentication(false);

            PrivateKey privateKey = SCPKIHelper.shared(appContext).getPrivateKey(specs, "test_keys");
            assertTrue(privateKey != null);
            return;
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertTrue(false);
    }
}
