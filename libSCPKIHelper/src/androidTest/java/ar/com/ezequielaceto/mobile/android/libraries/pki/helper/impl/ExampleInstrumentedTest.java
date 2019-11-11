package ar.com.ezequielaceto.mobile.android.libraries.pki.helper.impl;

import android.content.Context;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

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

    @Test
    public void importCertificateAsPEM() {
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        try {
            SCPKIKeySpec specs  = SCPKIKeySpec.common;
            specs.setRequireUserAuthentication(false);

            String pem = "-----BEGIN CERTIFICATE-----\n" +
                    "MIIDUzCCAjugAwIBAgIIc4DUJg/He0EwDQYJKoZIhvcNAQENBQAwODEaMBgGA1UEAwwRQ29tcHV0\n" +
                    "YWRvcmVzIFRlc3QxDTALBgNVBAoMBEFGSVAxCzAJBgNVBAYTAkFSMB4XDTE5MTEwNjE1MjU1NFoX\n" +
                    "DTIxMTEwNTE1MjU1NFowOTEcMBoGA1UEAwwTVEVTVEZBQ1RVUkFET1JNT1ZJTDEZMBcGA1UEBRMQ\n" +
                    "Q1VJVCAyNzMyNjYwOTAyNzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZ1er/Kv/2z\n" +
                    "Qn+XaYi6mnCBcpj27/lW+gvYeDfaUmj49BAmMpTAOezxr/IE8F0eiaOvfaVa2UTqfZ2ra/j6+/5j\n" +
                    "O3+u8VOB2J0UBqJT69ZF2d1Snj/gCIADO8IJWM68jtXKrHR1t5uYMY9Lhfp4NI1c27Znwz+FaF7o\n" +
                    "ZWX390KhI5E6OU2G+lfRj2M8FD0kGYsRwildnuRS9OHI7R1Jr96E7hHnISD1Bx8Ow3QZ+BLI6RAp\n" +
                    "BbgaIF4NI7XOLWq09JMv8rN1XR9GIcNYgAahFSd5VoE1MhHA3LKwcLIJIFMo5FDy2ihoH8nuIBsw\n" +
                    "TUrFRlDfpUwIjtfFpQdzvnJZqO8CAwEAAaNgMF4wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBSz\n" +
                    "stP//em63t6NrxEhnNYgffJPbzAdBgNVHQ4EFgQUifxY3VDy94nRvKP9qWi2foYSrugwDgYDVR0P\n" +
                    "AQH/BAQDAgXgMA0GCSqGSIb3DQEBDQUAA4IBAQCZQ21i0j3KmsYeLFSXtAmTTWanBs+ZALTJE9Jj\n" +
                    "mhsFYZCV6CI/hhL4h4w2OSofzfLdt76cLCDdNokI+pZAvXEs0DZnMVUDCOnhxqoafC2eVADi04sj\n" +
                    "AHx6bUnKfmUvHgLs4tRZk2ysQ3+eCegYmxqhkOEQKIAd/7JclT4T6sMystf5kyMiZxDCehKwy407\n" +
                    "RL0YIVRVvlGpELVHLw7Y1aGFXAk/gHsltcUwwgDjwos0QWdSZSe2NRjPev8DIAYZgmG/Lyc6UFc2\n" +
                    "ADt8GWwSDBKZG2GR+XnsRFkPiqcL3IeRR/hD6lKuhYTZRkwnOizM0s/p2rTDtWud7oZ1UFsQwzJI\n" +
                    "-----END CERTIFICATE----";

            Certificate importedCert = SCPKIHelper.shared(appContext).importCertificate(specs, "test_cert", pem);

            assertTrue(importedCert != null);
            return;
        } catch (Exception e) {
            e.printStackTrace();
        }
        assertTrue(false);
    }
}
