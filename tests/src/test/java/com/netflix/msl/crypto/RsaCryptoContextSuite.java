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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.RsaCryptoContext.Mode;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * RSA crypto context unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({RsaCryptoContextSuite.EncryptDecrypt.class,
               RsaCryptoContextSuite.WrapUnwrap.class,
               RsaCryptoContextSuite.SignVerify.class})
public class RsaCryptoContextSuite{
    /** Key pair ID. */
    private static final String KEYPAIR_ID = "keypairid";
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;

    @BeforeClass
    public static synchronized void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidParameterSpecException, NoSuchProviderException, MslEncodingException, MslCryptoException {
        if (random == null) {
            ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            encoder = ctx.getMslEncoderFactory();
            Security.addProvider(new BouncyCastleProvider());
            
            final KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("RSA");
            keypairGenerator.initialize(512);
            final KeyPair keypairA = keypairGenerator.generateKeyPair();
            privateKeyA = keypairA.getPrivate();
            publicKeyA = keypairA.getPublic();
            
            final KeyPair keypairB = keypairGenerator.generateKeyPair();
            privateKeyB = keypairB.getPrivate();
            publicKeyB = keypairB.getPublic();
    
            random = new Random();
        }
    }
    
    @AfterClass
    public static synchronized void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }
    
    /** Encrypt/decrypt mode unit tests. */
    @RunWith(Parameterized.class)
    public static class EncryptDecrypt {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Parameters
        public static Collection<Object[]> data() {
            return Arrays.asList(new Object[][] {
                { Mode.ENCRYPT_DECRYPT_OAEP, 16 },
                { Mode.ENCRYPT_DECRYPT_PKCS1, 32 }
            });
        }
        
        /** Crypto context mode. */
        private final Mode mode;
        /** Plaintext message size in bytes. */
        private final int messageSize;
        
        /**
         * Create a new encrypt/decrypt test instance with the specified
         * mode and plaintext message size.
         * 
         * @param mode crypto context mode.
         * @param messageSize plaintext message size in bytes.
         */
        public EncryptDecrypt(final Mode mode, final int messageSize) {
            this.mode = mode;
            this.messageSize = messageSize;
        }
        
        @Test
        public void encryptDecrypt() throws MslEncodingException, MslCryptoException, MslMasterTokenException {
            final byte[] messageA = new byte[messageSize];
            random.nextBytes(messageA);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            final byte[] ciphertextA = cryptoContext.encrypt(messageA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertThat(messageA, is(not(ciphertextA)));
            
            final byte[] plaintextA = cryptoContext.decrypt(ciphertextA, encoder);
            assertNotNull(plaintextA);
            assertArrayEquals(messageA, plaintextA);
            
            final byte[] messageB = new byte[messageSize];
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
        public void encryptNullPublic() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.ENCRYPT_NOT_SUPPORTED);

            final byte[] message = new byte[messageSize];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
            cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
        }
        
        @Test
        public void decryptNullPrivate() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.DECRYPT_NOT_SUPPORTED);

            final byte[] message = new byte[messageSize];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
            final byte[] ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
            cryptoContext.decrypt(ciphertext, encoder);
        }
        
        @Test
        public void encryptDecryptIdMismatch() throws MslCryptoException {
            final byte[] message = new byte[messageSize];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID + "A", privateKeyA, publicKeyA, mode);
            final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertThat(message, is(not(ciphertext)));
            
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID + "B", privateKeyA, publicKeyA, mode);
            final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void encryptDecryptKeysMismatch() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.CIPHERTEXT_BAD_PADDING);

            final byte[] message = new byte[messageSize];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
            
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);
            cryptoContextB.decrypt(ciphertext, encoder);
        }

        @Test
        public void wrapUnwrapOneBlock() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            
            final byte[] keydataA = new byte[8];
            random.nextBytes(keydataA);
            
            final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertArrayEquals(keydataA, ciphertextA);
        }

        @Test
        public void wrapUnwrapBlockAligned() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            
            final byte[] keydataA = new byte[messageSize];
            random.nextBytes(keydataA);
            
            final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertArrayEquals(keydataA, ciphertextA);
        }

        @Test
        public void wrapUnwrapBlockUnaligned() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            
            final byte[] keydataA = new byte[127];
            random.nextBytes(keydataA);
            
            final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertArrayEquals(keydataA, ciphertextA);
        }
        
        @Test
        public void wrapNullPublic() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
            
            final byte[] messageA = new byte[messageSize];
            random.nextBytes(messageA);
            
            final byte[] ciphertextA = cryptoContext.wrap(messageA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertArrayEquals(messageA, ciphertextA);
        }

        @Test
        public void unwrapNullPrivate() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
            
            final byte[] messageA = new byte[messageSize];
            random.nextBytes(messageA);

            final byte[] plaintextA = cryptoContext.unwrap(messageA, encoder);
            assertNotNull(plaintextA);
            assertArrayEquals(messageA, plaintextA);
        }

        @Test
        public void unwrapUnalignedData() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            
            final byte[] keydataA = new byte[1];
            random.nextBytes(keydataA);

            final byte[] plaintextA = cryptoContext.unwrap(keydataA, encoder);
            assertNotNull(plaintextA);
            assertArrayEquals(keydataA, plaintextA);
        }
        
        @Test
        public void signVerify() throws MslCryptoException {
            final byte[] message = new byte[messageSize];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            final byte[] signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
            assertNotNull(signature);
            assertEquals(0, signature.length);
            
            assertTrue(cryptoContext.verify(message, signature, encoder));
        }
        
        @Test
        public void signVerifyContextMismatch() throws MslCryptoException {
            final byte[] message = new byte[messageSize];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, mode);
            final byte [] signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, mode);
            assertTrue(cryptoContextB.verify(message, signature, encoder));
        }
        
        @Test
        public void signNullPrivate() throws MslCryptoException {
            final byte[] message = new byte[messageSize];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, mode);
            final byte[] signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
            assertNotNull(signature);
            assertEquals(0, signature.length);
            
            assertTrue(cryptoContext.verify(message, signature, encoder));
        }
        
        @Test
        public void verifyNullPublic() throws MslCryptoException {
            final byte[] message = new byte[messageSize];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, mode);
            final byte[] signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
            assertNotNull(signature);
            assertEquals(0, signature.length);
            
            assertTrue(cryptoContext.verify(message, signature, encoder));
        }
    }

    /** Wrap/unwrap mode unit tests. */
    @Ignore
    public static class WrapUnwrap {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void encryptDecrypt() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void encryptNullPublic() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void decryptNullPrivate() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void encryptDecryptIdMismatch() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID + "A", privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID + "B", privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void encryptDecryptKeysMismatch() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, Mode.SIGN_VERIFY);
            final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void wrapUnwrapOneBlock() throws MslCryptoException {
            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.WRAP_UNWRAP);
            
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
            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.WRAP_UNWRAP);
            
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
        public void wrapUnwrapBlockUnaligned() throws MslCryptoException {
            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.WRAP_UNWRAP);
            
            final byte[] keydataA = new byte[127];
            random.nextBytes(keydataA);
            
            final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertThat(keydataA, is(not(ciphertextA)));
            
            final byte[] plaintextA = cryptoContext.unwrap(ciphertextA, encoder);
            assertNotNull(plaintextA);
            assertArrayEquals(keydataA, plaintextA);
            
            final byte[] keydataB = new byte[127];
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
        public void wrapNullPublic() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, Mode.WRAP_UNWRAP);
            
            final byte[] messageA = new byte[32];
            random.nextBytes(messageA);
            
            cryptoContext.wrap(messageA, encoder, ENCODER_FORMAT);
        }
        
        @Test
        public void unwrapNullPrivate() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, Mode.WRAP_UNWRAP);
            
            final byte[] messageA = new byte[32];
            random.nextBytes(messageA);
            
            cryptoContext.unwrap(messageA, encoder);
        }
        
        @Test
        public void unwrapUnalignedData() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.INVALID_WRAP_CIPHERTEXT);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.WRAP_UNWRAP);
            
            final byte[] keydataA = new byte[1];
            random.nextBytes(keydataA);
            
            cryptoContext.unwrap(keydataA, encoder);
        }
        
        @Test
        public void signVerify() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.WRAP_UNWRAP);
            final byte[] signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
            assertNotNull(signature);
            assertEquals(0, signature.length);
            
            assertTrue(cryptoContext.verify(message, signature, encoder));
        }
        
        @Test
        public void signVerifyContextMismatch() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.WRAP_UNWRAP);
            final byte [] signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, Mode.WRAP_UNWRAP);
            assertTrue(cryptoContextB.verify(message, signature, encoder));
        }
        
        @Test
        public void signNullPrivate() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, Mode.WRAP_UNWRAP);
            final byte[] signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
            assertNotNull(signature);
            assertEquals(0, signature.length);
            
            assertTrue(cryptoContext.verify(message, signature, encoder));
        }
        
        @Test
        public void verifyNullPublic() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, Mode.WRAP_UNWRAP);
            final byte[] signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
            assertNotNull(signature);
            assertEquals(0, signature.length);
            
            assertTrue(cryptoContext.verify(message, signature, encoder));
        }
    }
    
    /** Sign/verify mode unit tests. */
    public static class SignVerify {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void encryptDecrypt() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void encryptNullPublic() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void decryptNullPrivate() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContext.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final byte[] plaintext = cryptoContext.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void encryptDecryptIdMismatch() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID + "A", privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID + "B", privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void encryptDecryptKeysMismatch() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);
            
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, Mode.SIGN_VERIFY);
            final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }
        
        @Test
        public void wrapUnwrapOneBlock() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            
            final byte[] keydataA = new byte[8];
            random.nextBytes(keydataA);
            
            final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertArrayEquals(keydataA, ciphertextA);
        }
        
        @Test
        public void wrapUnwrapBlockAligned() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            
            final byte[] keydataA = new byte[32];
            random.nextBytes(keydataA);
            
            final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertArrayEquals(keydataA, ciphertextA);
        }
        
        @Test
        public void wrapUnwrapBlockUnaligned() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            
            final byte[] keydataA = new byte[127];
            random.nextBytes(keydataA);
            
            final byte[] ciphertextA = cryptoContext.wrap(keydataA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertArrayEquals(keydataA, ciphertextA);
        }
        
        @Test
        public void wrapNullPublic() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.WRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, Mode.SIGN_VERIFY);
            
            final byte[] messageA = new byte[32];
            random.nextBytes(messageA);
            
            final byte[] ciphertextA = cryptoContext.wrap(messageA, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertextA);
            assertArrayEquals(messageA, ciphertextA);
        }
        
        @Test
        public void unwrapNullPrivate() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, Mode.SIGN_VERIFY);
            
            final byte[] messageA = new byte[32];
            random.nextBytes(messageA);

            final byte[] plaintextA = cryptoContext.unwrap(messageA, encoder);
            assertNotNull(plaintextA);
            assertArrayEquals(messageA, plaintextA);
        }
        
        @Test
        public void unwrapUnalignedData() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.UNWRAP_NOT_SUPPORTED);

            final ICryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            
            final byte[] keydataA = new byte[1];
            random.nextBytes(keydataA);

            final byte[] plaintextA = cryptoContext.unwrap(keydataA, encoder);
            assertNotNull(plaintextA);
            assertArrayEquals(keydataA, plaintextA);
        }
        
        @Test
        public void signVerify() throws MslCryptoException {
            final byte[] messageA = new byte[32];
            random.nextBytes(messageA);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
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
        public void signVerifyContextMismatch() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContextA = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte [] signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);
            final RsaCryptoContext cryptoContextB = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyB, publicKeyB, Mode.SIGN_VERIFY);
            assertFalse(cryptoContextB.verify(message, signature, encoder));
        }
        
        @Test
        public void signNullPrivate() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.SIGN_NOT_SUPPORTED);

            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, null, publicKeyA, Mode.SIGN_VERIFY);
            cryptoContext.sign(message, encoder, ENCODER_FORMAT);
        }
        
        @Test
        public void verifyNullPublic() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.VERIFY_NOT_SUPPORTED);

            final byte[] message = new byte[32];
            random.nextBytes(message);
            
            final RsaCryptoContext cryptoContext = new RsaCryptoContext(ctx, KEYPAIR_ID, privateKeyA, null, Mode.SIGN_VERIFY);
            final byte[] signature;
            try {
                signature = cryptoContext.sign(message, encoder, ENCODER_FORMAT);
            } catch (final MslCryptoException e) {
                fail(e.getMessage());
                return;
            }
            cryptoContext.verify(message, signature, encoder);
        }
    }
    
    /** RSA public key A. */
    private static PublicKey publicKeyA;
    /** RSA private key A. */
    private static PrivateKey privateKeyA;
    /** RSA public key B. */
    private static PublicKey publicKeyB;
    /** RSA private key B. */
    private static PrivateKey privateKeyB;
    /** MSL context. */
    private static MslContext ctx;
    /** Random. */
    private static Random random;
}
