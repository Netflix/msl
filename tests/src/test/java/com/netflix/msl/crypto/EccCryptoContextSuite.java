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

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.crypto.EccCryptoContext.Mode;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;

/**
 * ECC crypto context unit tests.
 *
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({EccCryptoContextSuite.EncryptDecrypt.class,
               EccCryptoContextSuite.SignVerify.class})
public class EccCryptoContextSuite {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key pair ID. */
    private static final String KEYPAIR_ID = "keypairid";

    /** EC curve q. */
    private static final BigInteger EC_Q = new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839");
    /** EC coefficient a. */
    private static final BigInteger EC_A = new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16);
    /** EC coefficient b. */
    private static final BigInteger EC_B = new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16);

    /** EC base point g. */
    private static final BigInteger EC_G = new BigInteger("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf", 16);
    /** EC generator order n. */
    private static final BigInteger EC_N = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");



    @AfterClass
    public static synchronized void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }

    /** Encrypt/decrypt mode unit tests. */
    @Ignore // Cannot perform ECIES encryption/decryption at the moment.
    public static class EncryptDecrypt {

    }

    /** Sign/verify mode unit tests. */
    public static class SignVerify {
        @BeforeClass
        public static synchronized void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidParameterSpecException, NoSuchProviderException, MslEncodingException, MslCryptoException {
            if (random == null) {
                Security.addProvider(new BouncyCastleProvider());
                final MslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
                encoder = ctx.getMslEncoderFactory();

                final ECCurve curve = new ECCurve.Fp(EC_Q, EC_A, EC_B);
                final AlgorithmParameterSpec paramSpec = new ECParameterSpec(curve, curve.decodePoint(EC_G.toByteArray()), EC_N);
                final KeyPairGenerator keypairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
                keypairGenerator.initialize(paramSpec);
                final KeyPair keypairA = keypairGenerator.generateKeyPair();
                privateKeyA = keypairA.getPrivate();
                publicKeyA = keypairA.getPublic();
                keypairGenerator.initialize(paramSpec);
                final KeyPair keypairB = keypairGenerator.generateKeyPair();
                privateKeyB = keypairB.getPrivate();
                publicKeyB = keypairB.getPublic();

                random = new Random();
            }
        }

        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();

        @Test
        public void encryptDecrypt() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);

            final EccCryptoContext cryptoContext = new EccCryptoContext(KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
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

            final EccCryptoContext cryptoContext = new EccCryptoContext(KEYPAIR_ID, privateKeyA, null, Mode.SIGN_VERIFY);
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

            final EccCryptoContext cryptoContext = new EccCryptoContext(KEYPAIR_ID, null, publicKeyA, Mode.SIGN_VERIFY);
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

            final EccCryptoContext cryptoContextA = new EccCryptoContext(KEYPAIR_ID + "A", privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);

            final EccCryptoContext cryptoContextB = new EccCryptoContext(KEYPAIR_ID + "B", privateKeyB, publicKeyB, Mode.SIGN_VERIFY);
            final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }

        @Test
        public void encryptDecryptKeyMismatch() throws MslCryptoException {
            final byte[] message = new byte[32];
            random.nextBytes(message);

            final EccCryptoContext cryptoContextA = new EccCryptoContext(KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] ciphertext = cryptoContextA.encrypt(message, encoder, ENCODER_FORMAT);
            assertNotNull(ciphertext);
            assertArrayEquals(message, ciphertext);

            final EccCryptoContext cryptoContextB = new EccCryptoContext(KEYPAIR_ID, privateKeyB, publicKeyB, Mode.SIGN_VERIFY);
            final byte[] plaintext = cryptoContextB.decrypt(ciphertext, encoder);
            assertNotNull(plaintext);
            assertArrayEquals(message, plaintext);
        }

        @Test
        public void signVerify() throws MslCryptoException {
            final byte[] messageA = new byte[32];
            random.nextBytes(messageA);

            final EccCryptoContext cryptoContext = new EccCryptoContext(KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
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

            final EccCryptoContext cryptoContextA = new EccCryptoContext(KEYPAIR_ID, privateKeyA, publicKeyA, Mode.SIGN_VERIFY);
            final byte[] signature = cryptoContextA.sign(message, encoder, ENCODER_FORMAT);

            final EccCryptoContext cryptoContextB = new EccCryptoContext(KEYPAIR_ID, privateKeyB, publicKeyB, Mode.SIGN_VERIFY);
            assertFalse(cryptoContextB.verify(message, signature, encoder));
        }

        @Test
        public void signNullPrivate() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.SIGN_NOT_SUPPORTED);

            final byte[] message = new byte[32];
            random.nextBytes(message);

            final EccCryptoContext cryptoContext = new EccCryptoContext(KEYPAIR_ID, null, publicKeyA, Mode.SIGN_VERIFY);
            cryptoContext.sign(message, encoder, ENCODER_FORMAT);
        }

        @Test
        public void verifyNullPublic() throws MslCryptoException {
            thrown.expect(MslCryptoException.class);
            thrown.expectMslError(MslError.VERIFY_NOT_SUPPORTED);

            final byte[] message = new byte[32];
            random.nextBytes(message);

            final EccCryptoContext cryptoContext = new EccCryptoContext(KEYPAIR_ID, privateKeyA, null, Mode.SIGN_VERIFY);
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

    /** ECC public key A. */
    private static PublicKey publicKeyA;
    /** ECC private key A. */
    private static PrivateKey privateKeyA;
    /** ECC public key B. */
    private static PublicKey publicKeyB;
    /** ECC private key B. */
    private static PrivateKey privateKeyB;
    /** Random. */
    private static Random random;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
}
