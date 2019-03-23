package com.google.webauthn.gaedemo.customTests;

import co.nstant.in.cbor.CborException;
import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.webauthn.gaedemo.exceptions.ResponseException;
import com.google.webauthn.gaedemo.objects.AuthenticatorAssertionResponse;
import com.google.webauthn.gaedemo.objects.AuthenticatorData;
import com.google.webauthn.gaedemo.objects.CollectedClientData;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class ExtendsTest {
    package com.google.webauthn.gaedemo.customTests;

import co.nstant.in.cbor.CborException;
import com.google.common.io.BaseEncoding;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.webauthn.gaedemo.exceptions.ResponseException;
import com.google.webauthn.gaedemo.objects.AuthenticatorAssertionResponse;
import com.google.webauthn.gaedemo.objects.AuthenticatorData;
import com.google.webauthn.gaedemo.objects.CollectedClientData;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

    public class ExtendsTest extends TestCase {

        final SecureRandom random = new SecureRandom();

        /**
         * Test method for
         * {@link com.google.webauthn.gaedemo.objects.AuthenticatorAssertionResponse#AuthenticatorAssertionResponse(java.lang.String)}.
         *
         * @throws ResponseException
         */

        // @Test
        public void testAuthenticatorAssertionResponseWithTestComment() throws ResponseException {
            Gson gson = new Gson();
            CollectedClientData clientData = new CollectedClientData();
            clientData.challenge = "challengeString";
            clientData.hashAlgorithm = "SHA-256";
            clientData.origin = "https://localhost";
            String clientJson =
                    BaseEncoding.base64().encode(gson.toJson(clientData).getBytes(StandardCharsets.UTF_8));
            AuthenticatorData authData = null;

            {
                byte flags = 1 << 6;
                byte[] rpIdHash = new byte[32];

                authData = new AuthenticatorData(rpIdHash, flags, 0);
            }

            String authenticatorBase64 = null;
            try {
                authenticatorBase64 = BaseEncoding.base64().encode(authData.encode());
            } catch (CborException e1) {
                fail(e1.toString());
            }

            byte[] signature = new byte[32];
            random.nextBytes(signature);
            String signatureBase64 = BaseEncoding.base64().encode(signature);

            JsonObject json = new JsonObject();
            json.addProperty("clientDataJSON", clientJson);
            json.addProperty("authenticatorData", authenticatorBase64);
            json.addProperty("signature", signatureBase64);

            JsonElement element = gson.fromJson(json.toString(), JsonElement.class);
            System.out.println(json.toString());
            AuthenticatorAssertionResponse decoded = new AuthenticatorAssertionResponse(element);
            assertTrue(Arrays.equals(decoded.signature, signature));
            assertEquals(decoded.getClientData(), clientJson);
            assertEquals(decoded.getAuthenticatorData(), authData);
        }

        public void testAuthenticatorAssertionResponseWithoutTestComment() throws ResponseException {
            Gson gson = new Gson();
            CollectedClientData clientData = new CollectedClientData();
            clientData.challenge = "challengeString";
            clientData.hashAlgorithm = "SHA-256";
            clientData.origin = "https://localhost";
            String clientJson =
                    BaseEncoding.base64().encode(gson.toJson(clientData).getBytes(StandardCharsets.UTF_8));
            AuthenticatorData authData = null;

            {
                byte flags = 1 << 6;
                byte[] rpIdHash = new byte[32];

                authData = new AuthenticatorData(rpIdHash, flags, 0);
            }

            String authenticatorBase64 = null;
            try {
                authenticatorBase64 = BaseEncoding.base64().encode(authData.encode());
            } catch (CborException e1) {
                fail(e1.toString());
            }

            byte[] signature = new byte[32];
            random.nextBytes(signature);
            String signatureBase64 = BaseEncoding.base64().encode(signature);

            JsonObject json = new JsonObject();
            json.addProperty("clientDataJSON", clientJson);
            json.addProperty("authenticatorData", authenticatorBase64);
            json.addProperty("signature", signatureBase64);

            JsonElement element = gson.fromJson(json.toString(), JsonElement.class);
            System.out.println(json.toString());
            AuthenticatorAssertionResponse decoded = new AuthenticatorAssertionResponse(element);
            assertTrue(Arrays.equals(decoded.signature, signature));
            assertEquals(decoded.getClientData(), clientJson);
            assertEquals(decoded.getAuthenticatorData(), authData);
        }
    }

}
