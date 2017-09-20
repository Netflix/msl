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
import java.util.List;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * Symmetric crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Parameterized.class)
public class SymmetricCryptoContextTest {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key set ID. */
    private static final String KEYSET_ID = "keysetid";
    /** Key ciphertext. */
    private static final String KEY_CIPHERTEXT = "ciphertext";
    
    /** AES-128 CMAC key length in bytes. */
    private static final int AES_CMAC_KEY_LENGTH = 16;
    
    /** RFC 3394 encryption key. */
    private final byte[] RFC_KEY = {
        (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
        (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F };
    /** RFC 3394 plaintext (key data). */
    private final byte[] RFC_PLAINTEXT = {
        (byte)0x00, (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77,
        (byte)0x88, (byte)0x99, (byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD, (byte)0xEE, (byte)0xFF };
    /** RFC 3394 ciphertext. */
    private final byte[] RFC_CIPHERTEXT = {
        (byte)0x1F, (byte)0xA6, (byte)0x8B, (byte)0x0A, (byte)0x81, (byte)0x12, (byte)0xB4, (byte)0x47,
        (byte)0xAE, (byte)0xF3, (byte)0x4B, (byte)0xD8, (byte)0xFB, (byte)0x5A, (byte)0x7B, (byte)0x82,
        (byte)0x9D, (byte)0x3E, (byte)0x86, (byte)0x23, (byte)0x71, (byte)0xD2, (byte)0xCF, (byte)0xE5 };

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        random = new Random();
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
    }
    
    @AfterClass
    public static void teardown() {
        encoder = null;
        ctx = null;
        random = null;
    }
    
    @Parameters
    public static List<Object[]> data() {
        final byte[] aesKey = new byte[AES_CMAC_KEY_LENGTH];
        new Random().nextBytes(aesKey);
        final SecretKey aesCmacKey = new SecretKeySpec(aesKey, JcaAlgorithm.AES_CMAC);
        return Arrays.asList(new Object[][] {
            { MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW },
            { MockPresharedAuthenticationFactory.KPE, aesCmacKey, MockPresharedAuthenticationFactory.KPW },
        });
    }
    
    /** Crypto context. */
    private final ICryptoContext cryptoContext;
    
    /**
     * Create a new symmetric crypto context test instance.
     * 
     * @param encryptionKey encryption key.
     * @param signatureKey signature key.
     * @param wrappingKey wrpaping key.
     */
    public SymmetricCryptoContextTest(final SecretKey encryptionKey, final SecretKey signatureKey, final SecretKey wrappingKey) {
        this.cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, encryptionKey, signatureKey, wrappingKey);
    }
    
    @Test
    public void encryptDecrypt() throws MslEncodingException, MslCryptoException, MslMasterTokenException {
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
    public void invalidCiphertext() throws MslEncodingException, MslCryptoException, MslEncoderException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

        final byte[] message = new byte[32];
        random.nextBytes(message);

        final byte[] data = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        final MslObject envelopeMo = encoder.parseObject(data);
        final MslCiphertextEnvelope envelope = new MslCiphertextEnvelope(envelopeMo);
        final byte[] ciphertext = envelope.getCiphertext();
        ++ciphertext[ciphertext.length - 2];
        final MslCiphertextEnvelope shortEnvelope = new MslCiphertextEnvelope(envelope.getKeyId(), envelope.getIv(), ciphertext);
        cryptoContext.decrypt(shortEnvelope.toMslEncoding(encoder, ENCODER_FORMAT), encoder);
    }

    @Test
    public void insufficientCiphertext() throws MslCryptoException, MslEncoderException, MslEncodingException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE);

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
    public void notEnvelope() throws MslCryptoException, MslEncoderException, MslEncodingException, UnsupportedEncodingException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

        final byte[] message = new byte[32];
        random.nextBytes(message);

        final byte[] data = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        final MslObject envelopeMo = encoder.parseObject(data);
        envelopeMo.remove(KEY_CIPHERTEXT);
        cryptoContext.decrypt(encoder.encodeObject(envelopeMo, ENCODER_FORMAT), encoder);
    }
    
    @Test
    public void corruptEnvelope() throws MslCryptoException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ENVELOPE_PARSE_ERROR);

        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final byte[] data = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        data[0] = 0;
        cryptoContext.decrypt(data, encoder);
    }
    
    @Test
    public void encryptNullEncryption() throws MslEncodingException, MslCryptoException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.ENCRYPT_NOT_SUPPORTED);

        final ICryptoContext cryptoContext= new SymmetricCryptoContext(ctx, KEYSET_ID, null, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT);
    }
    
    @Test
    public void decryptNullEncryption() throws MslEncodingException, MslCryptoException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.DECRYPT_NOT_SUPPORTED);

        final ICryptoContext cryptoContext= new SymmetricCryptoContext(ctx, KEYSET_ID, null, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        cryptoContext.decrypt(messageA, encoder);
    }
    
    @Test
    public void encryptDecryptNullKeys() throws MslEncodingException, MslCryptoException, MslEncoderException {
        final ICryptoContext cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, null, null);
        
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
    public void encryptDecryptIdMismatch() throws MslEncodingException, MslCryptoException, MslEncoderException {
    	final ICryptoContext cryptoContextA = new SymmetricCryptoContext(ctx, KEYSET_ID + "A", MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
        final ICryptoContext cryptoContextB = new SymmetricCryptoContext(ctx, KEYSET_ID + "B", MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
        
        final byte[] message = new byte[32];
        random.nextBytes(message);
        
        final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertext);
        assertThat(ciphertext, is(not(message)));
        
        final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
        assertNotNull(plaintext);
        assertArrayEquals(message, plaintext);
    }
    
    @Test
    public void encryptDecryptKeysMismatch() throws MslEncodingException, MslCryptoException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

        final ICryptoContext cryptoContextA = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
        final ICryptoContext cryptoContextB = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE2, MockPresharedAuthenticationFactory.KPH2, MockPresharedAuthenticationFactory.KPW2);
        
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
    public void wrapUnwrapOneBlock() throws MslCryptoException {
        final byte[] keydataA = new byte[8];
        random.nextBytes(keydataA);
        
        final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextA);
        assertThat(keydataA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.unwrap(ciphertextA, encoder);
        assertNotNull(plaintextA);
        assertArrayEquals(keydataA, plaintextA);
        
        final byte[] keydataB = new byte[8];
        random.nextBytes(keydataB);
        
        final byte[] ciphertextB = cryptoContext.wrap(keydataB, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextB);
        assertThat(keydataB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.unwrap(ciphertextB, encoder);
        assertNotNull(plaintextB);
        assertArrayEquals(keydataB, plaintextB);
    }
    
    @Test
    public void wrapUnwrapBlockAligned() throws MslCryptoException {
        final byte[] keydataA = new byte[32];
        random.nextBytes(keydataA);
        
        final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextA);
        assertThat(keydataA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.unwrap(ciphertextA, encoder);
        assertNotNull(plaintextA);
        assertArrayEquals(keydataA, plaintextA);
        
        final byte[] keydataB = new byte[32];
        random.nextBytes(keydataB);
        
        final byte[] ciphertextB = cryptoContext.wrap(keydataB, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextB);
        assertThat(keydataB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.unwrap(ciphertextB, encoder);
        assertNotNull(plaintextB);
        assertArrayEquals(keydataB, plaintextB);
    }
    
    @Test
    public void wrapBlockUnaligned() throws MslCryptoException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.PLAINTEXT_ILLEGAL_BLOCK_SIZE);

        final byte[] keydataA = new byte[127];
        random.nextBytes(keydataA);
        
        cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
    }
    
    @Test
    public void unwrapBlockUnaligned() throws MslCryptoException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE);

        final byte[] ciphertextA = new byte[127];
        random.nextBytes(ciphertextA);
        
        cryptoContext.unwrap(ciphertextA, encoder);
    }
    
    @Test
    public void wrapNullWrap() throws MslCryptoException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

        final ICryptoContext cryptoContext= new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, null);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        cryptoContext.wrap(messageA, encoder, ENCODER_FORMAT);
    }
    
    @Test
    public void unwrapNullWrap() throws MslCryptoException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.UNWRAP_NOT_SUPPORTED);

        final ICryptoContext cryptoContext= new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, null);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        
        cryptoContext.unwrap(messageA, encoder);
    }
    
    @Test
    public void wrapUnwrapNullKeys() throws MslCryptoException {
        final ICryptoContext cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, null, null, MockPresharedAuthenticationFactory.KPW);
        
        final byte[] keydataA = new byte[32];
        random.nextBytes(keydataA);
        
        final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextA);
        assertThat(keydataA, is(not(ciphertextA)));
        
        final byte[] plaintextA = cryptoContext.unwrap(ciphertextA, encoder);
        assertNotNull(plaintextA);
        assertArrayEquals(keydataA, plaintextA);
        
        final byte[] keydataB = new byte[32];
        random.nextBytes(keydataB);
        
        final byte[] ciphertextB = cryptoContext.wrap(keydataB, encoder, ENCODER_FORMAT);
        assertNotNull(ciphertextB);
        assertThat(keydataB, is(not(ciphertextB)));
        assertThat(ciphertextB, is(not(ciphertextA)));
        
        final byte[] plaintextB = cryptoContext.unwrap(ciphertextB, encoder);
        assertNotNull(plaintextB);
        assertArrayEquals(keydataB, plaintextB);
    }
    
    @Test
    public void unwrapUnalignedData() throws MslCryptoException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.CIPHERTEXT_ILLEGAL_BLOCK_SIZE);

        final byte[] keydataA = new byte[1];
        random.nextBytes(keydataA);
        
        cryptoContext.unwrap(keydataA, encoder);
    }
    
    @Test
    public void rfcWrapUnwrap() throws MslEntityAuthException, MslCryptoException {
        final SecretKey wrappingKey = new SecretKeySpec(RFC_KEY, JcaAlgorithm.AESKW);
        final ICryptoContext cryptoContext = new SymmetricCryptoContext(ctx, "RFC", null, null, wrappingKey);
        
        final byte[] wrapped = cryptoContext.wrap(RFC_PLAINTEXT, encoder, ENCODER_FORMAT);
        assertArrayEquals(RFC_CIPHERTEXT, wrapped);
        
        final byte[] unwrapped = cryptoContext.unwrap(wrapped, encoder);
        assertArrayEquals(RFC_PLAINTEXT, unwrapped);
    }
    
    @Test
    public void signVerify() throws MslCryptoException, MslEncodingException, MslMasterTokenException {
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
    public void signVerifyContextMismatch() throws MslEncodingException, MslEncoderException, MslCryptoException {
        final ICryptoContext cryptoContextA = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, MockPresharedAuthenticationFactory.KPW);
        final ICryptoContext cryptoContextB = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE2, MockPresharedAuthenticationFactory.KPH2, MockPresharedAuthenticationFactory.KPW2);
        
        final byte[] message = new byte[32];
        random.nextBytes(message);
        final byte[] signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);
        assertFalse(cryptoContextB.verify(message, signature, encoder));
    }
    
    @Test
    public void signVerifyNullKeys() throws MslCryptoException, MslEncodingException, MslEncoderException {
        final ICryptoContext cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, null, MockPresharedAuthenticationFactory.KPH, null);
        
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
    public void signNullHmac() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.SIGN_NOT_SUPPORTED);

        final ICryptoContext cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, null, MockPresharedAuthenticationFactory.KPW);
        
        final byte[] messageA = new byte[32];
        random.nextBytes(messageA);
        cryptoContext.sign(messageA, encoder, ENCODER_FORMAT);
    }
    
    @Test
    public void verifyNullHmac() throws MslCryptoException, MslEncodingException, MslEncoderException {
        thrown.expect(MslCryptoException.class);
        thrown.expectMslError(MslError.VERIFY_NOT_SUPPORTED);

        final ICryptoContext cryptoContext = new SymmetricCryptoContext(ctx, KEYSET_ID, MockPresharedAuthenticationFactory.KPE, null, MockPresharedAuthenticationFactory.KPW);
        
        final byte[] message = new byte[32];
        random.nextBytes(message);
        final byte[] signature = new byte[32];
        random.nextBytes(signature);
        cryptoContext.verify(message, signature, encoder);
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Random. */
    private static Random random;
}
