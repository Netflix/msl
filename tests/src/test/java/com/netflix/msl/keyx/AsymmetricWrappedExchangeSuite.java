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
package com.netflix.msl.keyx;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Random;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.keyx.AsymmetricWrappedExchange.RequestData;
import com.netflix.msl.keyx.AsymmetricWrappedExchange.RequestData.Mechanism;
import com.netflix.msl.keyx.AsymmetricWrappedExchange.ResponseData;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Asymmetric wrapped key exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({AsymmetricWrappedExchangeSuite.RequestDataTest.class,
               AsymmetricWrappedExchangeSuite.RequestDataTest.Params.class,
               AsymmetricWrappedExchangeSuite.ResponseDataTest.class,
               AsymmetricWrappedExchangeSuite.KeyExchangeFactoryTest.class,
               AsymmetricWrappedExchangeSuite.KeyExchangeFactoryTest.Params.class})
public class AsymmetricWrappedExchangeSuite {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

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

    /** Key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key key request data. */
    private static final String KEY_KEYDATA = "keydata";
    
    /** Key key pair ID. */
    private static final String KEY_KEY_PAIR_ID = "keypairid";
    /** Key encrypted encryption key. */
    private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
    /** Key encrypted HMAC key. */
    private static final String KEY_HMAC_KEY = "hmackey";
    
    private static final String KEYPAIR_ID = "keypairId";
    private static PublicKey ECC_PUBLIC_KEY;
    private static PrivateKey ECC_PRIVATE_KEY;
    private static PublicKey RSA_PUBLIC_KEY;
    private static PrivateKey RSA_PRIVATE_KEY;
    
    private static final String IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    private static MasterToken MASTER_TOKEN;
    private static byte[] ENCRYPTION_KEY;
    private static byte[] HMAC_KEY;
    
    @BeforeClass
    public static synchronized void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslEncodingException, MslCryptoException {
        if (ctx == null) {
            Security.addProvider(new BouncyCastleProvider());
            
            final ECCurve curve = new ECCurve.Fp(EC_Q, EC_A, EC_B);
            final AlgorithmParameterSpec paramSpec = new ECParameterSpec(curve, curve.decodePoint(EC_G.toByteArray()), EC_N);
            final KeyPairGenerator eccGenerator = KeyPairGenerator.getInstance("ECIES");
            eccGenerator.initialize(paramSpec);
            final KeyPair eccKeyPair = eccGenerator.generateKeyPair();
            ECC_PUBLIC_KEY = eccKeyPair.getPublic();
            ECC_PRIVATE_KEY = eccKeyPair.getPrivate();
            
            final KeyPairGenerator rsaGenerator = KeyPairGenerator.getInstance("RSA");
            rsaGenerator.initialize(2048);
            final KeyPair rsaKeyPair = rsaGenerator.generateKeyPair();
            RSA_PUBLIC_KEY = rsaKeyPair.getPublic();
            RSA_PRIVATE_KEY = rsaKeyPair.getPrivate();
    
            ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            encoder = ctx.getMslEncoderFactory();
            MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1, 1);
            ENCRYPTION_KEY = MASTER_TOKEN.getEncryptionKey().getEncoded();
            HMAC_KEY = MASTER_TOKEN.getSignatureKey().getEncoded();
        }
    }
    
    @AfterClass
    public static synchronized void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    
    /** Request data unit tests. */
    public static class RequestDataTest {
        /** Key key pair ID. */
        private static final String KEY_KEY_PAIR_ID = "keypairid";
        /** Key mechanism. */
        private static final String KEY_MECHANISM = "mechanism";
        /** Key public key. */
        private static final String KEY_PUBLIC_KEY = "publickey";
        
        @RunWith(Parameterized.class)
        public static class Params {
            @Rule
            public ExpectedMslException thrown = ExpectedMslException.none();
            
            @Parameters
            public static Collection<Object[]> data() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslEncodingException, MslCryptoException {
                AsymmetricWrappedExchangeSuite.setup();
                return Arrays.asList(new Object[][] {
                    { Mechanism.RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWEJS_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWK_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWK_RSAES, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                });
            }

            /** Key exchange mechanism. */
            private final Mechanism mechanism;
            /** Public key. */
            private final PublicKey publicKey;
            /** Private key. */
            private final PrivateKey privateKey;

            /**
             * Create a new request data test instance with the specified key
             * exchange parameters.
             * 
             * @param mechanism key exchange mechanism.
             * @param publicKey public key.
             * @param privateKey private key.
             */
            public Params(final Mechanism mechanism, final PublicKey publicKey, final PrivateKey privateKey) {
                this.mechanism = mechanism;
                this.publicKey = publicKey;
                this.privateKey = privateKey;
            }

            @Test
            public void ctors() throws MslException, MslEncodingException, MslCryptoException, MslKeyExchangeException, MslEncoderException {
                final RequestData req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                assertEquals(KeyExchangeScheme.ASYMMETRIC_WRAPPED, req.getKeyExchangeScheme());
                assertEquals(KEYPAIR_ID, req.getKeyPairId());
                assertEquals(mechanism, req.getMechanism());
                assertArrayEquals(privateKey.getEncoded(), req.getPrivateKey().getEncoded());
                assertArrayEquals(publicKey.getEncoded(), req.getPublicKey().getEncoded());
                final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
                assertNotNull(keydata);

                final RequestData moReq = new RequestData(keydata);
                assertEquals(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
                assertEquals(req.getKeyPairId(), moReq.getKeyPairId());
                assertEquals(req.getMechanism(), moReq.getMechanism());
                assertNull(moReq.getPrivateKey());
                assertArrayEquals(req.getPublicKey().getEncoded(), moReq.getPublicKey().getEncoded());
                final MslObject moKeydata = moReq.getKeydata(encoder, ENCODER_FORMAT);
                assertNotNull(moKeydata);
                assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
            }

            @Test
            public void mslObject() throws MslException, MslEncoderException {
                final RequestData req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final MslObject mo = MslTestUtils.toMslObject(encoder, req);
                assertEquals(KeyExchangeScheme.ASYMMETRIC_WRAPPED.toString(), mo.getString(KEY_SCHEME));
                final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
                assertEquals(KEYPAIR_ID, keydata.getString(KEY_KEY_PAIR_ID));
                assertEquals(mechanism.toString(), keydata.getString(KEY_MECHANISM));
                assertArrayEquals(publicKey.getEncoded(), keydata.getBytes(KEY_PUBLIC_KEY));
            }

            @Test
            public void create() throws MslException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslEncoderException {
                final RequestData data = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final MslObject mo = MslTestUtils.toMslObject(encoder, data);
                final KeyRequestData keyRequestData = KeyRequestData.create(ctx, mo);
                assertNotNull(keyRequestData);
                assertTrue(keyRequestData instanceof RequestData);

                final RequestData moData = (RequestData)keyRequestData;
                assertEquals(data.getKeyExchangeScheme(), moData.getKeyExchangeScheme());
                assertEquals(data.getKeyPairId(), moData.getKeyPairId());
                assertEquals(data.getMechanism(), moData.getMechanism());
                assertNull(moData.getPrivateKey());
                assertArrayEquals(data.getPublicKey().getEncoded(), moData.getPublicKey().getEncoded());
            }

            @Test
            public void missingKeypairId() throws MslException, MslEncodingException, MslCryptoException, MslKeyExchangeException {
                thrown.expect(MslEncodingException.class);
                thrown.expectMslError(MslError.MSL_PARSE_ERROR);

                final RequestData req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);

                assertNotNull(keydata.remove(KEY_KEY_PAIR_ID));

                new RequestData(keydata);
            }

            @Test
            public void missingMechanism() throws MslException, MslEncodingException, MslCryptoException, MslKeyExchangeException {
                thrown.expect(MslEncodingException.class);
                thrown.expectMslError(MslError.MSL_PARSE_ERROR);

                final RequestData req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);

                assertNotNull(keydata.remove(KEY_MECHANISM));

                new RequestData(keydata);
            }

            @Test
            public void invalidMechanism() throws MslException, MslEncodingException, MslCryptoException, MslKeyExchangeException {
                thrown.expect(MslKeyExchangeException.class);
                thrown.expectMslError(MslError.UNIDENTIFIED_KEYX_MECHANISM);

                final RequestData req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);

                keydata.put(KEY_MECHANISM, "x");

                new RequestData(keydata);
            }

            @Test
            public void missingPublicKey() throws MslException, MslEncodingException, MslCryptoException, MslKeyExchangeException {
                thrown.expect(MslEncodingException.class);
                thrown.expectMslError(MslError.MSL_PARSE_ERROR);

                final RequestData req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);

                assertNotNull(keydata.remove(KEY_PUBLIC_KEY));

                new RequestData(keydata);
            }

            @Test
            public void invalidPublicKey() throws MslException, MslEncodingException, MslCryptoException, MslKeyExchangeException {
                thrown.expect(MslCryptoException.class);
                thrown.expectMslError(MslError.INVALID_PUBLIC_KEY);

                final RequestData req = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);

                final byte[] encodedKey = publicKey.getEncoded();
                final byte[] shortKey = Arrays.copyOf(encodedKey, encodedKey.length / 2);
                keydata.put(KEY_PUBLIC_KEY, shortKey);

                new RequestData(keydata);
            }
        }

        @Test
        public void equalsKeyPairId() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final RequestData dataA = new RequestData(KEYPAIR_ID + "A", Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataB = new RequestData(KEYPAIR_ID + "B", Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the parse constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }

        @Test
        public void equalsMechanism() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final RequestData dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataB = new RequestData(KEYPAIR_ID, Mechanism.ECC, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the parse constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }

        @Test
        public void equalsPublicKey() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final RequestData dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataB = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, ECC_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the parse constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }

        @Test
        public void equalsPrivateKey() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final RequestData dataA = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final RequestData dataB = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, ECC_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));

            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());

            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the parse constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }

        @Test
        public void equalsObject() {
            final RequestData data = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            assertFalse(data.equals(null));
            assertFalse(data.equals(IDENTITY));
            assertTrue(data.hashCode() != IDENTITY.hashCode());
        }
    }

    /** Response data unit tests. */
    public static class ResponseDataTest {
        /** Key master token. */
        private static final String KEY_MASTER_TOKEN = "mastertoken";
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctors() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            assertArrayEquals(ENCRYPTION_KEY, resp.getEncryptionKey());
            assertArrayEquals(HMAC_KEY, resp.getHmacKey());
            assertEquals(KeyExchangeScheme.ASYMMETRIC_WRAPPED, resp.getKeyExchangeScheme());
            assertEquals(KEYPAIR_ID, resp.getKeyPairId());
            assertEquals(MASTER_TOKEN, resp.getMasterToken());
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);

            final ResponseData moResp = new ResponseData(MASTER_TOKEN, keydata);
            assertArrayEquals(resp.getEncryptionKey(), moResp.getEncryptionKey());
            assertArrayEquals(resp.getHmacKey(), moResp.getHmacKey());
            assertEquals(resp.getKeyExchangeScheme(), moResp.getKeyExchangeScheme());
            assertEquals(resp.getKeyPairId(), moResp.getKeyPairId());
            assertEquals(resp.getMasterToken(), moResp.getMasterToken());
            final MslObject moKeydata = moResp.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }
        
        @Test
        public void mslObject() throws MslException, MslEncodingException, MslCryptoException, MslException, MslEncoderException {
            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, resp);
            assertEquals(KeyExchangeScheme.ASYMMETRIC_WRAPPED.toString(), mo.getString(KEY_SCHEME));
            final MasterToken masterToken = new MasterToken(ctx, mo.getMslObject(KEY_MASTER_TOKEN, encoder));
            assertEquals(MASTER_TOKEN, masterToken);
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            assertEquals(KEYPAIR_ID, keydata.getString(KEY_KEY_PAIR_ID));
            assertArrayEquals(ENCRYPTION_KEY, keydata.getBytes(KEY_ENCRYPTION_KEY));
            assertArrayEquals(HMAC_KEY, keydata.getBytes(KEY_HMAC_KEY));
        }
        
        @Test
        public void create() throws MslException, MslException, MslEncoderException {
            final ResponseData data = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, data);
            final KeyResponseData keyResponseData = KeyResponseData.create(ctx, mo);
            assertNotNull(keyResponseData);
            assertTrue(keyResponseData instanceof ResponseData);
            
            final ResponseData moData = (ResponseData)keyResponseData;
            assertArrayEquals(data.getEncryptionKey(), moData.getEncryptionKey());
            assertArrayEquals(data.getHmacKey(), moData.getHmacKey());
            assertEquals(data.getKeyExchangeScheme(), moData.getKeyExchangeScheme());
            assertEquals(data.getKeyPairId(), moData.getKeyPairId());
            assertEquals(data.getMasterToken(), moData.getMasterToken());
        }

        @Test
        public void missingKeyPairId() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            assertNotNull(keydata.remove(KEY_KEY_PAIR_ID));

            new ResponseData(MASTER_TOKEN, keydata);
        }

        @Test
        public void missingEncryptionKey() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            assertNotNull(keydata.remove(KEY_ENCRYPTION_KEY));

            new ResponseData(MASTER_TOKEN, keydata);
        }

        @Test
        public void missingHmacKey() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            assertNotNull(keydata.remove(KEY_HMAC_KEY));

            new ResponseData(MASTER_TOKEN, keydata);
        }
        
        @Test
        public void equalsMasterToken() throws MslEncodingException, MslException, MslCryptoException, MslKeyExchangeException, MslEncoderException {
            final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
            final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
            final ResponseData dataA = new ResponseData(masterTokenA, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataB = new ResponseData(masterTokenB, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(masterTokenA, dataA.getKeydata(encoder, ENCODER_FORMAT));
            
            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());
            
            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());
            
            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            assertEquals(dataA.hashCode(), dataA2.hashCode());
        }
        
        @Test
        public void equalsKeyPairId() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            final ResponseData dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID + "A", ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));
            
            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());
            
            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());
            
            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            assertEquals(dataA.hashCode(), dataA2.hashCode());
        }
        
        @Test
        public void equalsEncryptionKey() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            final byte[] encryptionKeyA = Arrays.copyOf(ENCRYPTION_KEY, ENCRYPTION_KEY.length);
            final byte[] encryptionKeyB = Arrays.copyOf(ENCRYPTION_KEY, ENCRYPTION_KEY.length);
            ++encryptionKeyB[0];
            final ResponseData dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyA, HMAC_KEY);
            final ResponseData dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, encryptionKeyB, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));
            
            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());
            
            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());
            
            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            assertEquals(dataA.hashCode(), dataA2.hashCode());
        }
        
        @Test
        public void equalsHmacKey() throws MslEncodingException, MslException, MslKeyExchangeException, MslEncoderException {
            final byte[] hmacKeyA = Arrays.copyOf(HMAC_KEY, HMAC_KEY.length);
            final byte[] hmacKeyB = Arrays.copyOf(HMAC_KEY, HMAC_KEY.length);
            ++hmacKeyB[0];
            final ResponseData dataA = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyA);
            final ResponseData dataB = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, hmacKeyB);
            final ResponseData dataA2 = new ResponseData(MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));
            
            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());
            
            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());
            
            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            assertEquals(dataA.hashCode(), dataA2.hashCode());
        }
        
        @Test
        public void equalsObject() {
            final ResponseData data = new ResponseData(MASTER_TOKEN, KEYPAIR_ID, ENCRYPTION_KEY, HMAC_KEY);
            assertFalse(data.equals(null));
            assertFalse(data.equals(IDENTITY));
            assertTrue(data.hashCode() != IDENTITY.hashCode());
        }
    }
    
    /** Key exchange factory unit tests. */
    public static class KeyExchangeFactoryTest {
        /**
         * Fake key request data for the asymmetric wrapped key exchange
         * scheme.
         */
        private static class FakeKeyRequestData extends KeyRequestData {
            /** Create a new fake key request data. */
            protected FakeKeyRequestData() {
                super(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            }

            /* (non-Javadoc)
             * @see com.netflix.msl.keyx.KeyRequestData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
             */
            @Override
            protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
                return null;
            }
        }
        
        /**
         * Fake key response data for the asymmetric wrapped key exchange
         * scheme.
         */
        private static class FakeKeyResponseData extends KeyResponseData {
            /** Create a new fake key response data. */
            protected FakeKeyResponseData() {
                super(MASTER_TOKEN, KeyExchangeScheme.ASYMMETRIC_WRAPPED);
            }

            /* (non-Javadoc)
             * @see com.netflix.msl.keyx.KeyResponseData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
             */
            @Override
            protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
                return null;
            }
        }
        
        /**
         * @param ctx MSL context.
         * @param encryptionKey master token encryption key.
         * @param hmacKey master token HMAC key.
         * @return a new master token.
         * @throws MslEncodingException if there is an error encoding the data.
         * @throws MslCryptoException if there is an error encrypting or signing
         *         the token data.
         * @throws MslException if the master token is constructed incorrectly.
         * @throws MslException if there is an error editing the data.
         * @throws MslEncoderException if there is an error modifying the data.
         */
        private static MasterToken getUntrustedMasterToken(final MslContext ctx, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslEncodingException, MslCryptoException, MslException, MslException, MslEncoderException {
            final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
            final Date expiration = new Date(System.currentTimeMillis() + 2000);
            final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
            final MasterToken masterToken = new MasterToken(ctx, renewalWindow, expiration, 1L, 1L, null, identity, encryptionKey, hmacKey);
            final MslObject mo = MslTestUtils.toMslObject(encoder, masterToken);
            final byte[] signature = mo.getBytes("signature");
            ++signature[1];
            mo.put("signature", signature);
            final MasterToken untrustedMasterToken = new MasterToken(ctx, mo);
            return untrustedMasterToken;
        }

        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @BeforeClass
        public static synchronized void setup() {
            Security.addProvider(new BouncyCastleProvider());
            random = new Random();
            authutils = new MockAuthenticationUtils();
            factory = new AsymmetricWrappedExchange(authutils);
            entityAuthData = new PresharedAuthenticationData(IDENTITY);
        }
        
        @AfterClass
        public static void teardown() {
            // Do not cleanup so the static instances are available to
            // subclasses.
        }
        
        @Before
        public void reset() {
            authutils.reset();
            ctx.getMslStore().clearCryptoContexts();
            ctx.getMslStore().clearServiceTokens();
        }

        @RunWith(Parameterized.class)
        public static class Params {
            @Rule
            public ExpectedMslException thrown = ExpectedMslException.none();
            
            @Parameters
            public static Collection<Object[]> data() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslEncodingException, MslCryptoException {
                AsymmetricWrappedExchangeSuite.setup();
                return Arrays.asList(new Object[][] {
                    { Mechanism.RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWEJS_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWK_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                    { Mechanism.JWK_RSAES, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY },
                });
            }

            /** Key exchange mechanism. */
            private final Mechanism mechanism;
            /** Public key. */
            private final PublicKey publicKey;
            /** Private key. */
            private final PrivateKey privateKey;

            /**
             * Create a new request data test instance with the specified key
             * exchange parameters.
             * 
             * @param mechanism key exchange mechanism.
             * @param publicKey public key.
             * @param privateKey private key.
             */
            public Params(final Mechanism mechanism, final PublicKey publicKey, final PrivateKey privateKey) {
                this.mechanism = mechanism;
                this.publicKey = publicKey;
                this.privateKey = privateKey;
            }

            @Test
            public void generateInitialResponse() throws MslException, MslException {
                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
                assertNotNull(keyxData);
                assertNotNull(keyxData.cryptoContext);
                assertNotNull(keyxData.keyResponseData);

                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                assertEquals(KeyExchangeScheme.ASYMMETRIC_WRAPPED, keyResponseData.getKeyExchangeScheme());
                final MasterToken masterToken = keyResponseData.getMasterToken();
                assertNotNull(masterToken);
                assertEquals(IDENTITY, masterToken.getIdentity());
            }

            @Test
            public void generateSubsequentResponse() throws MslException {
                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
                assertNotNull(keyxData);
                assertNotNull(keyxData.cryptoContext);
                assertNotNull(keyxData.keyResponseData);

                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                assertEquals(KeyExchangeScheme.ASYMMETRIC_WRAPPED, keyResponseData.getKeyExchangeScheme());
                final MasterToken masterToken = keyResponseData.getMasterToken();
                assertNotNull(masterToken);
                assertEquals(MASTER_TOKEN.getIdentity(), masterToken.getIdentity());
                assertEquals(MASTER_TOKEN.getSerialNumber(), masterToken.getSerialNumber());
                assertEquals(MASTER_TOKEN.getSequenceNumber() + 1, masterToken.getSequenceNumber());
            }

            @Test
            public void untrustedMasterTokenSubsequentResponse() throws MslEncodingException, MslCryptoException, MslException, MslException, MslEncoderException {
                thrown.expect(MslMasterTokenException.class);

                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
                final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
                final MasterToken masterToken = getUntrustedMasterToken(ctx, encryptionKey, hmacKey);
                factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, masterToken);
            }

            @Test
            public void getCryptoContext() throws MslException {
                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
                final ICryptoContext requestCryptoContext = keyxData.cryptoContext;
                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                final ICryptoContext responseCryptoContext = factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null);
                assertNotNull(responseCryptoContext);

                final byte[] data = new byte[32];
                random.nextBytes(data);

                // Ciphertext won't always be equal depending on how it was
                // enveloped. So we cannot check for equality or inequality.
                final byte[] requestCiphertext = requestCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
                final byte[] responseCiphertext = responseCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
                assertFalse(Arrays.equals(data, requestCiphertext));
                assertFalse(Arrays.equals(data, responseCiphertext));

                // Signatures should always be equal.
                final byte[] requestSignature = requestCryptoContext.sign(data, encoder, ENCODER_FORMAT);
                final byte[] responseSignature = responseCryptoContext.sign(data, encoder, ENCODER_FORMAT);
                assertFalse(Arrays.equals(data, requestSignature));
                assertFalse(Arrays.equals(data, responseSignature));
                assertArrayEquals(requestSignature, responseSignature);

                // Plaintext should always be equal to the original message.
                final byte[] requestPlaintext = requestCryptoContext.decrypt(responseCiphertext, encoder);
                final byte[] responsePlaintext = responseCryptoContext.decrypt(requestCiphertext, encoder);
                assertNotNull(requestPlaintext);
                assertArrayEquals(data, requestPlaintext);
                assertArrayEquals(requestPlaintext, responsePlaintext);

                // Verification should always succeed.
                assertTrue(requestCryptoContext.verify(data, responseSignature, encoder));
                assertTrue(responseCryptoContext.verify(data, requestSignature, encoder));
            }

            @Test
            public void invalidWrappedEncryptionKeyCryptoContext() throws MslException, MslException, MslEncoderException {
                thrown.expect(MslCryptoException.class);

                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                final MasterToken masterToken = keyResponseData.getMasterToken();

                final MslObject keydata = keyResponseData.getKeydata(encoder, ENCODER_FORMAT);
                final byte[] wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);
                // I think I have to change length - 2 because of padding.
                ++wrappedEncryptionKey[wrappedEncryptionKey.length-2];
                keydata.put(KEY_ENCRYPTION_KEY, wrappedEncryptionKey);
                final byte[] wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);

                final KeyResponseData invalidKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
                factory.getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, null);
            }

            @Test
            public void invalidWrappedHmacKeyCryptoContext() throws MslException, MslException, MslEncoderException {
                thrown.expect(MslCryptoException.class);

                final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, mechanism, publicKey, privateKey);
                final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
                final KeyResponseData keyResponseData = keyxData.keyResponseData;
                final MasterToken masterToken = keyResponseData.getMasterToken();

                final MslObject keydata = keyResponseData.getKeydata(encoder, ENCODER_FORMAT);
                final byte[] wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);
                // I think I have to change length - 2 because of padding.
                ++wrappedHmacKey[wrappedHmacKey.length-2];
                keydata.put(KEY_HMAC_KEY, wrappedHmacKey);
                final byte[] wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);

                final KeyResponseData invalidKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID, wrappedEncryptionKey, wrappedHmacKey);
                factory.getCryptoContext(ctx, keyRequestData, invalidKeyResponseData, null);
            }
        }
        
        @Test
        public void factory() {
            assertEquals(KeyExchangeScheme.ASYMMETRIC_WRAPPED, factory.getScheme());
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestInitialResponse() throws MslInternalException, MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestSubsequentResponse() throws MslInternalException, MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            
            final KeyRequestData fakeKeyRequestData = new FakeKeyRequestData();
            factory.getCryptoContext(ctx, fakeKeyRequestData, keyResponseData, null);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongResponseCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
            final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID, Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final KeyResponseData fakeKeyResponseData = new FakeKeyResponseData();
            factory.getCryptoContext(ctx, keyRequestData, fakeKeyResponseData, null);
        }
        
        @Test
        public void keyIdMismatchCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_RESPONSE_REQUEST_MISMATCH);

            final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID + "A", Mechanism.JWE_RSA, RSA_PUBLIC_KEY, RSA_PRIVATE_KEY);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();
            
            final KeyResponseData mismatchedKeyResponseData = new ResponseData(masterToken, KEYPAIR_ID + "B", ENCRYPTION_KEY, HMAC_KEY);
            
            factory.getCryptoContext(ctx, keyRequestData, mismatchedKeyResponseData, null);
        }
        
        @Test
        public void missingPrivateKeyCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_PRIVATE_KEY_MISSING);

            final KeyRequestData keyRequestData = new RequestData(KEYPAIR_ID + "B", Mechanism.JWE_RSA, RSA_PUBLIC_KEY, null);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            
            factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null);
        }
        
        /** Random. */
        private static Random random;
        /** Authentication utilities. */
        private static MockAuthenticationUtils authutils;
        /** Key exchange factory. */
        private static KeyExchangeFactory factory;
        /** Entity authentication data. */
        private static EntityAuthenticationData entityAuthData;
    }
}

