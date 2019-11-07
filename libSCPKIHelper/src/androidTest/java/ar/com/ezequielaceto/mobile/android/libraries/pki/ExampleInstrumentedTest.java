package ar.com.ezequielaceto.mobile.android.libraries.pki;

import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyPair;

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class ExampleInstrumentedTest {
    @Test
    public void generateKeyPair() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        try {
            SCPKIKeySpec specs  = SCPKIKeySpec.common;
            specs.setRequireUserAuthentication(false);

            KeyPair keyPair = SCPKIHelper.shared(appContext).generateKeyPair(specs, "test_keys");
            assertTrue(keyPair != null && keyPair.getPrivate() != null && keyPair.getPublic() != null);
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertTrue(false);
    }
}
