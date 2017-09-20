/**
 * Copyright (c) 2012-2017 Netflix, Inc.  All rights reserved.
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

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Session crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SessionCryptoContextTest {
    /** Key ciphertext. */
    private final static String KEY_CIPHERTEXT = "ciphertext";
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /**
     * @param ctx MSL context.
     * @return a new master token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     */
    private static MasterToken getTrustedMasterToken(final MslContext ctx) throws MslEncodingException, MslCryptoException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, signatureKey);
        return masterToken;
    }
    
    /**
     * @param ctx MSL context.
     * @param encryptionKey master token encryption key.
     * @param signatureKey master token signature key.
     * @return a new master token.
     * @throws MslEncodingException if there is an error encoding the data.
     * @throws MslCryptoException if there is an error encrypting or signing
     *         the token data.
     * @throws MslException if the master token is constructed incorrectly.
     * @throws MslEncoderException if there is an error editing the data.
     */
    private static MasterToken getUntrustedMasterToken(final MslContext ctx, final SecretKey encryptionKey, final SecretKey signatureKey) throws MslEncodingException, MslCryptoException, MslException, MslEncoderException {
        final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
        final Date expiration = new Date(System.currentTimeMillis() + 2000);
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, signatureKey);
        final MslObject mo = MslTestUtils.toMslObject(encoder, masterToken);
        final byte[] signature = mo.getBytes("signature");
        ++signature[1];
        mo.put("signature", signature);
        final MasterToken untrustedMasterToken = new MasterToken(ctx, mo);
        return untrustedMasterToken;
    }
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Random. */
    private static Random random;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        random = new Random();
    }
    
    @AfterClass
    public static void teardown() {
        random = null;
        encoder = null;
        ctx = null;
    }
    
    @Test
    public void untrusted() throws MslEncoderException, MslException {
        thrown.expect(MslMasterTokenException.class);
        thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);

        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, signatureKey);
        new SessionCryptoContext(ctx, masterToken);
    }

    @Test
    public void encryptDecrypt() throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] ciphertextA = cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextA);
        assertThat(messageA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.decrypt(ciphertextA, encoder);
        assertNotNull(plaintextA);
        assertArrayEquals(messageA, plaintextA);
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] ciphertextB = cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextB);
        assertThat(messageB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.decrypt(ciphertextB, encoder);
        assertNotNull(plaintextB);
        assertArrayEquals(messageB, plaintextB);
    }
    
    @Test
    public void encryptDecryptKeys() throws MslEncoderException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, signatureKey);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, signatureKey);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] ciphertextA = cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextA);
        assertThat(messageA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.decrypt(ciphertextA, encoder);
        assertNotNull(plaintextA);
        assertArrayEquals(messageA, plaintextA);
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] ciphertextB = cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextB);
        assertThat(messageB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.decrypt(ciphertextB, encoder);
        assertNotNull(plaintextB);
        assertArrayEquals(messageB, plaintextB);
    }
    
    @Test
    public void invalidCiphertext() throws MslEncodingException, MslCryptoException, MslEncoderException, MslMasterTokenException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] message = new byte[32];
        random.nextBytes(message);

        final byte[] data = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        final MslObject envelopeMo = encoder.parseObject(data);
        final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(envelopeMo);
        final byte[] ciphertext = envelope.getCiphertext();
        ++ciphertext[ciphertext.length - 1];
        final MslCiphertextEnvelope shortEnvelope = new MslCiphertextEnvelope(envelope.getKeyId(), envelope.getIv(), ciphertext);
        cryptoContext.decrypt(shortEnvelope.toMslEncoding(encoder, ENCODER_FORMAT), encoder);
    }
    
    // I want this to catch the ArrayIndexOutOfBounds
    // MslError.INSUFFICIENT_CIPHERTEXT but I'm not sure how to trigger it
    // anymore.
    @Test
    public void insufficientCiphertext() throws MslCryptoException, MslEncoderException, MslEncodingException, MslMasterTokenException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE);

        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] message = new byte[32];
        random.nextBytes(message);

        final byte[] data = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        final MslObject envelopeMo = encoder.parseObject(data);
        final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(envelopeMo);
        final byte[] ciphertext = envelope.getCiphertext();
        
        final byte[] shortCiphertext = Arrays.copyOf(ciphertext, ciphertext.length - 1);
        final MslCiphertextEnvelope shortEnvelope = new MslCiphertextEnvelope(envelope.getKeyId(), envelope.getIv(), shortCiphertext);
        cryptoContext.decrypt(shortEnvelope.toMslEncoding(encoder, ENCODER_FORMAT), encoder);
    }
    
    @Test
    public void notEnvelope() throws MslCryptoException, MslEncoderException, MslEncodingException, MslMasterTokenException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] message = new byte[32];
        random.nextBytes(message);

        final byte[] data = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        final MslObject envelopeMo = encoder.parseObject(data);
        envelopeMo.remove(KEY_CIPHERTEXT);
        cryptoContext.decrypt(encoder.encodeObject(envelopeMo, ENCODER_FORMAT), encoder);
    }
    
    @Test
    public void corruptEnvelope() throws MslCryptoException, MslEncodingException, MslMasterTokenException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);

        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final byte[] data = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        data[0] = 0;
        cryptoContext.decrypt(data, encoder);
    }
    
    @Test
    public void encryptDecryptNullEncryption() throws MslEncoderException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.ENCRYPT_NOT_SUPPORTED);

        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken;
        try {
            masterToken = getUntrustedMasterToken(ctx, encryptionKey, signatureKey);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, null, signatureKey);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT);
    }
    
    @Test
    public void encryptDecryptNullSignature() throws MslEncoderException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, signatureKey);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, null);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] ciphertextA = cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextA);
        assertThat(messageA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.decrypt(ciphertextA, encoder);
        assertNotNull(plaintextA);
        assertArrayEquals(messageA, plaintextA);
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] ciphertextB = cryptoContext.encrypt(messageB, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextB);
        assertThat(messageB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.decrypt(ciphertextB, encoder);
        assertNotNull(plaintextB);
        assertArrayEquals(messageB, plaintextB);
    }
    
    @Test
    public void encryptDecryptIdMismatch() throws MslEncoderException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken;
        try {
            masterToken = getUntrustedMasterToken(ctx, encryptionKey, signatureKey);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        // With untrusted master tokens, there is no way of verifying the
        // identity provided against the internals of the master token. So this
        // test makes use of two session crypto contexts with different
        // identities.
        final SessionCryptoContext cryptoContextA = new SessionCryptoContext(ctx, masterToken, identity + "A", encryptionKey, signatureKey);
        final SessionCryptoContext cryptoContextB = new SessionCryptoContext(ctx, masterToken, identity + "B", encryptionKey, signatureKey);
        
        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertext);
        assertThat(message, is(not(ciphertext)));
        
        final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
        assertNotNull(plaintext);
        assertArrayEquals(message, plaintext);
    }
    
    @Test
    public void encryptDecryptKeysMismatch() throws MslEncoderException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKeyA = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKeyA = MockPresharedAuthenticationFactory.KPH;
        final SecretKey encryptionKeyB = MockPresharedAuthenticationFactory.KPE2;
        final SecretKey signatureKeyB = MockPresharedAuthenticationFactory.KPH2;
        final MasterToken masterTokenA, masterTokenB;
        try {
            masterTokenA = getUntrustedMasterToken(ctx, encryptionKeyA, signatureKeyA);
            masterTokenB = getUntrustedMasterToken(ctx, encryptionKeyB, signatureKeyB);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        final SessionCryptoContext cryptoContextA = new SessionCryptoContext(ctx, masterTokenA, identity, encryptionKeyA, signatureKeyA);
        final SessionCryptoContext cryptoContextB = new SessionCryptoContext(ctx, masterTokenB, identity, encryptionKeyB, signatureKeyB);

        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final byte[] ciphertext;
        try {
            ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        cryptoContextB.decrypt(ciphertext, encoder);
    }
    
    @Test
    public void signVerify() throws MslCryptoException, MslEncodingException, MslMasterTokenException {
        final MasterToken masterToken = getTrustedMasterToken(ctx);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] signatureA = cryptoContext.sign(messageA, encoder, ENCODER_FORMAT);
        assertNotNull(signatureA);
        assertTrue(signatureA.length > 0);
        assertThat(messageA, is(not(signatureA)));
        
        assertTrue(cryptoContext.verify(messageA, signatureA, encoder));
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] signatureB = cryptoContext.sign(messageB, encoder, ENCODER_FORMAT);
        assertTrue(signatureB.length > 0);
        assertThat(signatureA, is(not(signatureB)));
        
        assertTrue(cryptoContext.verify(messageB, signatureB, encoder));
        assertFalse(cryptoContext.verify(messageB, signatureA, encoder));
    }
    
    @Test
    public void signVerifyContextMismatch() throws MslEncoderException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKeyA = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKeyA = MockPresharedAuthenticationFactory.KPH;
        final SecretKey encryptionKeyB = MockPresharedAuthenticationFactory.KPE2;
        final SecretKey signatureKeyB = MockPresharedAuthenticationFactory.KPH2;
        final MasterToken masterTokenA, masterTokenB;
        try {
            masterTokenA = getUntrustedMasterToken(ctx, encryptionKeyA, signatureKeyA);
            masterTokenB = getUntrustedMasterToken(ctx, encryptionKeyB, signatureKeyB);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        
        final SessionCryptoContext cryptoContextA = new SessionCryptoContext(ctx, masterTokenA, identity, encryptionKeyA, signatureKeyA);
        final SessionCryptoContext cryptoContextB = new SessionCryptoContext(ctx, masterTokenB, identity, encryptionKeyB, signatureKeyB);

        final byte[] message = new byte[32];
        random.nextBytes(message);
        final byte[] signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);
        assertFalse(cryptoContextB.verify(message, signature, encoder));
    }
    
    @Test
    public void signVerifyKeys() throws MslEncoderException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, signatureKey);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, signatureKey);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] signatureA = cryptoContext.sign(messageA, encoder, ENCODER_FORMAT);
        assertNotNull(signatureA);
        assertTrue(signatureA.length > 0);
        assertThat(messageA, is(not(signatureA)));
        
        assertTrue(cryptoContext.verify(messageA, signatureA, encoder));
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] signatureB = cryptoContext.sign(messageB, encoder, ENCODER_FORMAT);
        assertTrue(signatureB.length > 0);
        assertThat(signatureA, is(not(signatureB)));
        
        assertTrue(cryptoContext.verify(messageB, signatureB, encoder));
        assertFalse(cryptoContext.verify(messageB, signatureA, encoder));
    }
    
    @Test
    public void signVerifyNullEncryption() throws MslEncoderException, MslException {
        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, signatureKey);
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, null, signatureKey);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        final byte[] signatureA = cryptoContext.sign(messageA, encoder, ENCODER_FORMAT);
        assertNotNull(signatureA);
        assertTrue(signatureA.length > 0);
        assertThat(messageA, is(not(signatureA)));
        
        assertTrue(cryptoContext.verify(messageA, signatureA, encoder));
        
        final byte[] messageB = new byte[32];
        random.nextBytes(messageB);
        
        final byte[] signatureB = cryptoContext.sign(messageB, encoder, ENCODER_FORMAT);
        assertTrue(signatureB.length > 0);
        assertThat(signatureA, is(not(signatureB)));
        
        assertTrue(cryptoContext.verify(messageB, signatureB, encoder));
        assertFalse(cryptoContext.verify(messageB, signatureA, encoder));
    }
    
    @Test
    public void verifyNullSignature() throws MslEncoderException, MslException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.SIGN_NOT_SUPPORTED);

        final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
        final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
        final SecretKey signatureKey = MockPresharedAuthenticationFactory.KPH;
        final MasterToken masterToken;
        try {
            masterToken = getUntrustedMasterToken(ctx, encryptionKey, signatureKey);
        } catch (final MslCryptoException e) {
            fail(e.getMessage());
            return;
        }
        final SessionCryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken, identity, encryptionKey, null);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        cryptoContext.sign(messageA, encoder, ENCODER_FORMAT);
    }
}
