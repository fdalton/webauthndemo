package com.google.webauthn.gaedemo.custom;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import com.google.webauthn.gaedemo.crypto.Crypto;
import com.google.webauthn.gaedemo.exceptions.WebAuthnException;
import com.google.webauthn.gaedemo.objects.Algorithm;
import com.google.webauthn.gaedemo.objects.AndroidSafetyNetAttestationStatement;
import com.google.webauthn.gaedemo.objects.RsaKey;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.Assert.fail;
import static org.junit.jupiter.api.AssertThrows.assertThrows;

public class StrangeCasesTest {

    @Rule
    public ExpectedException thrown= ExpectedException.none();

    @Test
    public void testAssertThrowsCborException() {
        SecureRandom random = new SecureRandom();
        AndroidSafetyNetAttestationStatement attStmt = new AndroidSafetyNetAttestationStatement();
        attStmt.ver = "10";
        attStmt.response = new byte[20];
        random.nextBytes(attStmt.response);

        try {
            DataItem encoded = attStmt.encode();
            assertThrows(CborException.class, AndroidSafetyNetAttestationStatement.decode(encoded), "AssertThrows inserted test - CborException");
        } catch (CborException e) {
            fail(e.getMessage());
        }
    }

    @Test
    public void testAssertThrowsWebAuthnExceptionn() {
        byte[] n = Hex.decode("A9E167983F39D55FF2A093415EA6798985C8355D9A915BFB1D01DA197026170FBDA522D035856D7A986614415CCFB7B7083B09C991B81969376DF9651E7BD9A93324A37F3BBBAF460186363432CB07035952FC858B3104B8CC18081448E64F1CFB5D60C4E05C1F53D37F53D86901F105F87A70D1BE83C65F38CF1C2CAA6AA7EB");
        byte[] e = Hex.decode("010001");
        Algorithm alg = Algorithm.RS256;
        RsaKey rsaPublicKey = new RsaKey(alg, n, e);
        assertThrows(WebAuthnException.class, Crypto.getRSAPublicKey(rsaPublicKey), "AssertThrows inserted test - WebAuthnException");
    }

    @Test
    public void testExpectMethodCallStandardException() {
        byte[] n = Hex.decode("A9E167983F39D55FF2A093415EA6798985C8355D9A915BFB1D01DA197026170FBDA522D035856D7A986614415CCFB7B7083B09C991B81969376DF9651E7BD9A93324A37F3BBBAF460186363432CB07035952FC858B3104B8CC18081448E64F1CFB5D60C4E05C1F53D37F53D86901F105F87A70D1BE83C65F38CF1C2CAA6AA7EB");
        byte[] e = Hex.decode("010001");

        Algorithm alg = Algorithm.RS256;
        RsaKey rsaPublicKey = new RsaKey(alg, n, e);
        thrown.expect(NullPointerException.class);
    }

    @Test
    public void testExpectMethodCallCustomException() {
        byte[] n = Hex.decode("A9E167983F39D55FF2A093415EA6798985C8355D9A915BFB1D01DA197026170FBDA522D035856D7A986614415CCFB7B7083B09C991B81969376DF9651E7BD9A93324A37F3BBBAF460186363432CB07035952FC858B3104B8CC18081448E64F1CFB5D60C4E05C1F53D37F53D86901F105F87A70D1BE83C65F38CF1C2CAA6AA7EB");
        byte[] e = Hex.decode("010001");

        Algorithm alg = Algorithm.RS256;
        RsaKey rsaPublicKey = new RsaKey(alg, n, e);
        thrown.expect(WebAuthnException.class);
    }

    @Test
    public void testExpectMethodCallNoException() {
        byte[] n = Hex.decode("A9E167983F39D55FF2A093415EA6798985C8355D9A915BFB1D01DA197026170FBDA522D035856D7A986614415CCFB7B7083B09C991B81969376DF9651E7BD9A93324A37F3BBBAF460186363432CB07035952FC858B3104B8CC18081448E64F1CFB5D60C4E05C1F53D37F53D86901F105F87A70D1BE83C65F38CF1C2CAA6AA7EB");
        byte[] e = Hex.decode("010001");

        Algorithm alg = Algorithm.RS256;
        RsaKey rsaPublicKey = new RsaKey(alg, n, e);
        thrown.expect("blablabla");
    }


    @Test(expected=NullPointerException.class)
    public void testExpectedAnnotationStandardException() {
        byte[] n = Hex.decode("A9E167983F39D55FF2A093415EA6798985C8355D9A915BFB1D01DA197026170FBDA522D035856D7A986614415CCFB7B7083B09C991B81969376DF9651E7BD9A93324A37F3BBBAF460186363432CB07035952FC858B3104B8CC18081448E64F1CFB5D60C4E05C1F53D37F53D86901F105F87A70D1BE83C65F38CF1C2CAA6AA7EB");
        byte[] e = Hex.decode("010001");

        Algorithm alg = Algorithm.RS256;
        RsaKey rsaPublicKey = new RsaKey(alg, n, e);
    }


    public void testFailOutsideATryCatch() {
        byte[] n = Hex.decode("A9E167983F39D55FF2A093415EA6798985C8355D9A915BFB1D01DA197026170FBDA522D035856D7A986614415CCFB7B7083B09C991B81969376DF9651E7BD9A93324A37F3BBBAF460186363432CB07035952FC858B3104B8CC18081448E64F1CFB5D60C4E05C1F53D37F53D86901F105F87A70D1BE83C65F38CF1C2CAA6AA7EB");
        byte[] e = Hex.decode("010001");

        Algorithm alg = Algorithm.RS256;
        RsaKey rsaPublicKey = new RsaKey(alg, n, e);
        fail( "Fail em uma parte aleatoria do codigo" );
    }

}
