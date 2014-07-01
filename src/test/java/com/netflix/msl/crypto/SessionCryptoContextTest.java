/**
 * Copyright (c) 2012-2014 Netflix, Inc.  All rights reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.netflix.msl.crypto;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * Session crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SessionCryptoContextTest {
    /** JSON key ciphertext. */
    private final static String KEY_CIPHERTEXT = "ciphertext";
    
    /**
     * @param ctx MSL context.
     * @return a new master token.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    private static MasterToken getTrustedMasterToken(final MslContext ctx) throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, hmacKey);
        return masterToken;
    }
    
    /**
     * @param ctx MSL context.
     * @param encryptionKey master token encryption key.
     * @param hmacKey master token HMAC key.
     * @return a new master token.
     * @throws MslEncodingException if there is an error encoding the JSON
     *         data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if the master token is constructed incorrectly.
     * @throws JSONException if there is an error editing the JSON data.
     */
    private static MasterToken getUntrustedMasterToken(final MslContext ctx, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslEncodingException, MslCryptoException, JSONException, MslException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, hmacKey);
        final String json = masterToken.toJSONString();
        final JSONObject jo = new JSONObject(json);
        final byte[] signature = DatatypeConverter.parseBase64Binary(jo.getString("signature"));
        ++signature[1];
        jo.put("signature", DatatypeConverter.printBase64Binary(signature));
        final MasterToken untrustedMasterToken = new MasterToken(ctx, jo);
        return untrustedMasterToken;
    }
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    /** MSL context. */
    private static MslContext ctx;
    /** Random. */
    private static Random random;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException { 
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        random = new Random();
    }
    
    @Test
    public void untrusted() throws JSONException, MslException {
        thrown.expect(MslMasterTokenException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);

        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
        new SessionCryptoContext(ctx, masterToken);
    }

    @Test
    public void encryptDecrypt() throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] ciphertextA = cryptoContext.encrypt(messageA);
        assertNotNull(ciphertextA);
        assertThat(messageA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.decrypt(ciphertextA);
        assertNotNull(plaintextA);
        assertArrayEquals(messageA, plaintextA);
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] ciphertextB = cryptoContext.encrypt(messageB);
        assertNotNull(ciphertextB);
        assertThat(messageB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.decrypt(ciphertextB);
        assertNotNull(plaintextB);
        assertArrayEquals(messageB, plaintextB);
    }
    
    @Test
    public void encryptDecryptKeys() throws JSONException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, hmacKey);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] ciphertextA = cryptoContext.encrypt(messageA);
        assertNotNull(ciphertextA);
        assertThat(messageA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.decrypt(ciphertextA);
        assertNotNull(plaintextA);
        assertArrayEquals(messageA, plaintextA);
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] ciphertextB = cryptoContext.encrypt(messageB);
        assertNotNull(ciphertextB);
        assertThat(messageB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.decrypt(ciphertextB);
        assertNotNull(plaintextB);
        assertArrayEquals(messageB, plaintextB);
    }
    
    @Test
    public void invalidCiphertext() throws MslEncodingException, MslCryptoException, JSONException, MslMasterTokenException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] message = new byte[32];
        random.nextBytes(message);

        final byte[] data = cryptoContext.encrypt(message);
        final JSONObject envelopeJo = new JSONObject(new String(data, MslConstants.DEFAULT_CHARSET));
        final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(envelopeJo);
        final byte[] ciphertext = envelope.getCiphertext();
        ++ciphertext[ciphertext.length - 1];
        final MslCiphertextEnvelope shortEnvelope = new MslCiphertextEnvelope(envelope.getKeyId(), envelope.getIv(), ciphertext);
        cryptoContext.decrypt(shortEnvelope.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
    }
    
    // I want this to catch the ArrayIndexOutOfBounds
    // MslError.INSUFFICIENT_CIPHERTEXT but I'm not sure how to trigger it
    // anymore.
    @Test
    public void insufficientCiphertext() throws MslCryptoException, JSONException, MslEncodingException, MslMasterTokenException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE);

        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] message = new byte[32];
        random.nextBytes(message);

        final byte[] data = cryptoContext.encrypt(message);
        final JSONObject envelopeJo = new JSONObject(new String(data, MslConstants.DEFAULT_CHARSET));
        final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(envelopeJo);
        final byte[] ciphertext = envelope.getCiphertext();
        
        final byte[] shortCiphertext = Arrays.copyOf(ciphertext, ciphertext.length - 1);
        final MslCiphertextEnvelope shortEnvelope = new MslCiphertextEnvelope(envelope.getKeyId(), envelope.getIv(), shortCiphertext);
        cryptoContext.decrypt(shortEnvelope.toJSONString().getBytes(MslConstants.DEFAULT_CHARSET));
    }
    
    @Test
    public void notEnvelope() throws MslCryptoException, JSONException, MslEncodingException, MslMasterTokenException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] message = new byte[32];
        random.nextBytes(message);

        final byte[] data = cryptoContext.encrypt(message);
        final JSONObject envelopeJo = new JSONObject(new String(data, MslConstants.DEFAULT_CHARSET));
        envelopeJo.remove(KEY_CIPHERTEXT);
        cryptoContext.decrypt(envelopeJo.toString().getBytes(MslConstants.DEFAULT_CHARSET));
    }
    
    @Test
    public void corruptEnvelope() throws MslCryptoException, MslEncodingException, MslMasterTokenException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final byte[] data = cryptoContext.encrypt(message);
        data[0] = 0;
        cryptoContext.decrypt(data);
    }
    
    @Test
    public void encryptDecryptNullEncryption() throws JSONException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.ENCRYPT_NOT_SUPPORTED);

        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken;
        try {
            masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, null, hmacKey);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        cryptoContext.encrypt(messageA);
    }
    
    @Test
    public void encryptDecryptNullHmac() throws JSONException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, null);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] ciphertextA = cryptoContext.encrypt(messageA);
        assertNotNull(ciphertextA);
        assertThat(messageA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.decrypt(ciphertextA);
        assertNotNull(plaintextA);
        assertArrayEquals(messageA, plaintextA);
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] ciphertextB = cryptoContext.encrypt(messageB);
        assertNotNull(ciphertextB);
        assertThat(messageB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.decrypt(ciphertextB);
        assertNotNull(plaintextB);
        assertArrayEquals(messageB, plaintextB);
    }
    
    @Test
    public void encryptDecryptIdMismatch() throws JSONException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.ENVELOPE_KEY_ID_MISMATCH);

        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken;
        try {
            masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        // With untrusted master tokens, there is no way of verifying the
        // identity provided against the internals of the master token. So this
        // test makes use of two session crypto contexts with different
        // identities.
        final SessionCryptoContext cryptoContextA = new SessionCryptoContext(ctx, masterToken, identity + "A", encryptionKey, hmacKey);
        final SessionCryptoContext cryptoContextB = new SessionCryptoContext(ctx, masterToken, identity + "B", encryptionKey, hmacKey);
        
        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final byte[] ciphertext;
        try {
            ciphertext = cryptoContextA.encrypt(message);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        cryptoContextB.decrypt(ciphertext);
    }
    
    @Test
    public void encryptDecryptKeysMismatch() throws JSONException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKeyA = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKeyA = MockPresharedAuthenticationFactory.KPH;
        final SecretKey encryptionKeyB = MockPresharedAuthenticationFactory.KPE2;
        final SecretKey hmacKeyB = MockPresharedAuthenticationFactory.KPH2;
        final MasterToken masterTokenA, masterTokenB;
        try {
            masterTokenA = getUntrustedMasterToken(ctx, encryptionKeyA, hmacKeyA);
            masterTokenB = getUntrustedMasterToken(ctx, encryptionKeyB, hmacKeyB);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        final SessionCryptoContext cryptoContextA = new SessionCryptoContext(ctx, masterTokenA, identity, encryptionKeyA, hmacKeyA);
        final SessionCryptoContext cryptoContextB = new SessionCryptoContext(ctx, masterTokenB, identity, encryptionKeyB, hmacKeyB);

        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final byte[] ciphertext;
        try {
            ciphertext = cryptoContextA.encrypt(message);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        cryptoContextB.decrypt(ciphertext);
    }
    
    @Test
    public void signVerify() throws MslCryptoException, MslEncodingException, MslMasterTokenException {
        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] signatureA = cryptoContext.sign(messageA);
        assertNotNull(signatureA);
        assertTrue(signatureA.length > 0);
        assertThat(messageA, is(not(signatureA)));
        
        assertTrue(cryptoContext.verify(messageA, signatureA));
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] signatureB = cryptoContext.sign(messageB);
        assertTrue(signatureB.length > 0);
        assertThat(signatureA, is(not(signatureB)));
        
        assertTrue(cryptoContext.verify(messageB, signatureB));
        assertFalse(cryptoContext.verify(messageB, signatureA));
    }
    
    @Test
    public void signVerifyContextMismatch() throws JSONException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKeyA = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKeyA = MockPresharedAuthenticationFactory.KPH;
        final SecretKey encryptionKeyB = MockPresharedAuthenticationFactory.KPE2;
        final SecretKey hmacKeyB = MockPresharedAuthenticationFactory.KPH2;
        final MasterToken masterTokenA, masterTokenB;
        try {
            masterTokenA = getUntrustedMasterToken(ctx, encryptionKeyA, hmacKeyA);
            masterTokenB = getUntrustedMasterToken(ctx, encryptionKeyB, hmacKeyB);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        final SessionCryptoContext cryptoContextA = new SessionCryptoContext(ctx, masterTokenA, identity, encryptionKeyA, hmacKeyA);
        final SessionCryptoContext cryptoContextB = new SessionCryptoContext(ctx, masterTokenB, identity, encryptionKeyB, hmacKeyB);

        final byte[] message = new byte[32];
        random.nextBytes(message);
        final byte[] signature = cryptoContextA.sign(message);
        assertFalse(cryptoContextB.verify(message, signature));
    }
    
    @Test
    public void signVerifyKeys() throws JSONException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, hmacKey);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] signatureA = cryptoContext.sign(messageA);
        assertNotNull(signatureA);
        assertTrue(signatureA.length > 0);
        assertThat(messageA, is(not(signatureA)));
        
        assertTrue(cryptoContext.verify(messageA, signatureA));
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] signatureB = cryptoContext.sign(messageB);
        assertTrue(signatureB.length > 0);
        assertThat(signatureA, is(not(signatureB)));
        
        assertTrue(cryptoContext.verify(messageB, signatureB));
        assertFalse(cryptoContext.verify(messageB, signatureA));
    }
    
    @Test
    public void signVerifyNullEncryption() throws JSONException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, null, hmacKey);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] signatureA = cryptoContext.sign(messageA);
        assertNotNull(signatureA);
        assertTrue(signatureA.length > 0);
        assertThat(messageA, is(not(signatureA)));
        
        assertTrue(cryptoContext.verify(messageA, signatureA));
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] signatureB = cryptoContext.sign(messageB);
        assertTrue(signatureB.length > 0);
        assertThat(signatureA, is(not(signatureB)));
        
        assertTrue(cryptoContext.verify(messageB, signatureB));
        assertFalse(cryptoContext.verify(messageB, signatureA));
    }
    
    @Test
    public void verifyNullHmac() throws JSONException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.SIGN_NOT_SUPPORTED);

        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken;
        try {
            masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, null);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        cryptoContext.sign(messageA);
    }
}
