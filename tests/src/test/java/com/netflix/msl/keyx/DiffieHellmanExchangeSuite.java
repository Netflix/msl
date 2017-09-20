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
import java.util.Arrays;
import java.util.Random;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
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
import com.netflix.msl.keyx.DiffieHellmanExchange.RequestData;
import com.netflix.msl.keyx.DiffieHellmanExchange.ResponseData;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Diffie-Hellman key exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({DiffieHellmanExchangeSuite.KeyExchangeFactoryTest.class,
               DiffieHellmanExchangeSuite.RequestDataTest.class,
               DiffieHellmanExchangeSuite.ResponseDataTest.class})
public class DiffieHellmanExchangeSuite {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key key request data. */
    private static final String KEY_KEYDATA = "keydata";
    
    /** Key Diffie-Hellman parameters ID. */
    private static final String KEY_PARAMETERS_ID = "parametersid";
    /** Key Diffie-Hellman public key. */
    private static final String KEY_PUBLIC_KEY = "publickey";
    
    /**
     * If the provided byte array begins with a null byte this function simply
     * returns the original array. Otherwise a new array is created that is a
     * copy of the original array with a null byte prepended, and this new array
     * is returned.
     * 
     * @param b the original array.
     * @return the resulting byte array.
     */
    private static byte[] prependNullByte(final byte[] b) {
        if (b[0] == 0x00)
            return b;
        final byte[] result = new byte[b.length + 1];
        result[0] = 0x00;
        System.arraycopy(b, 0, result, 1, b.length);
        return result;
    }
    
    private static MasterToken MASTER_TOKEN;
    private static final String PARAMETERS_ID = MockDiffieHellmanParameters.DEFAULT_ID;
    private static BigInteger REQUEST_PUBLIC_KEY;
    private static DHPrivateKey REQUEST_PRIVATE_KEY;
    private static BigInteger RESPONSE_PUBLIC_KEY;
    private static DHPrivateKey RESPONSE_PRIVATE_KEY;

    /** Random. */
    private static Random random;
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    
    @BeforeClass
    public static synchronized void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslEncodingException, MslCryptoException, MslKeyExchangeException {
        if (ctx == null) {
            random = new Random();
            
            ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            encoder = ctx.getMslEncoderFactory();
            MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1, 1);
            
            final DiffieHellmanParameters params = MockDiffieHellmanParameters.getDefaultParameters();
            final DHParameterSpec paramSpec = params.getParameterSpec(PARAMETERS_ID);
            final KeyPairGenerator generator = KeyPairGenerator.getInstance("DH");
            
            generator.initialize(paramSpec);
            final KeyPair requestKeyPair = generator.generateKeyPair();
            REQUEST_PUBLIC_KEY = ((DHPublicKey)requestKeyPair.getPublic()).getY();
            REQUEST_PRIVATE_KEY = (DHPrivateKey)requestKeyPair.getPrivate();
            
            generator.initialize(paramSpec);
            final KeyPair responseKeyPair = generator.generateKeyPair();
            RESPONSE_PUBLIC_KEY = ((DHPublicKey)responseKeyPair.getPublic()).getY();
            RESPONSE_PRIVATE_KEY = (DHPrivateKey)responseKeyPair.getPrivate();
        }
    }
    
    @AfterClass
    public static synchronized void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }
    
    /** Request data unit tests. */
    public static class RequestDataTest {
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctors() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            final RequestData req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            assertEquals(KeyExchangeScheme.DIFFIE_HELLMAN, req.getKeyExchangeScheme());
            assertEquals(PARAMETERS_ID, req.getParametersId());
            assertArrayEquals(REQUEST_PRIVATE_KEY.getEncoded(), req.getPrivateKey().getEncoded());
            assertEquals(REQUEST_PUBLIC_KEY, req.getPublicKey());
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);
            
            final RequestData moReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
            assertEquals(req.getParametersId(), moReq.getParametersId());
            assertNull(moReq.getPrivateKey());
            assertEquals(req.getPublicKey(), moReq.getPublicKey());
            final MslObject moKeydata = moReq.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }
        
        @Test
        public void mslObject() throws MslException, MslEncoderException {
            final RequestData req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, req);
            assertEquals(KeyExchangeScheme.DIFFIE_HELLMAN.toString(), mo.getString(KEY_SCHEME));
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            assertEquals(PARAMETERS_ID, keydata.getString(KEY_PARAMETERS_ID));
            assertArrayEquals(prependNullByte(REQUEST_PUBLIC_KEY.toByteArray()), keydata.getBytes(KEY_PUBLIC_KEY));
        }
        
        @Test
        public void create() throws MslException, MslEncodingException, MslEntityAuthException, MslCryptoException, MslKeyExchangeException, MslEncoderException {
            final RequestData data = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, data);
            final KeyRequestData keyRequestData = KeyRequestData.create(ctx, mo);
            assertNotNull(keyRequestData);
            assertTrue(keyRequestData instanceof RequestData);
            
            final RequestData moData = (RequestData)keyRequestData;
            assertEquals(data.getKeyExchangeScheme(), moData.getKeyExchangeScheme());
            assertEquals(data.getParametersId(), moData.getParametersId());
            assertNull(moData.getPrivateKey());
            assertEquals(data.getPublicKey(), moData.getPublicKey());
        }
        
        @Test
        public void missingParametersId() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final RequestData req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_PARAMETERS_ID));
            
            new RequestData(keydata);
        }
        
        @Test
        public void missingPublicKey() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final RequestData req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_PUBLIC_KEY));
            
            new RequestData(keydata);
        }
        
        @Test
        public void invalidPublicKey() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_INVALID_PUBLIC_KEY);

            final RequestData req = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            
            keydata.put(KEY_PUBLIC_KEY, new byte[0]);
            
            new RequestData(keydata);
        }
        
        @Test
        public void equalsParametersId() throws MslEncodingException, MslKeyExchangeException, MslException, MslEncoderException {
            final RequestData dataA = new RequestData(PARAMETERS_ID + "A", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final RequestData dataB = new RequestData(PARAMETERS_ID + "B", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));
            
            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());
            
            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());
            
            // The private keys don't transfer via the JSON constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }
        
        @Test
        public void equalsPublicKey() throws MslEncodingException, MslKeyExchangeException, MslException, MslEncoderException {
            final RequestData dataA = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final RequestData dataB = new RequestData(PARAMETERS_ID, RESPONSE_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));
            
            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());
            
            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());

            // The private keys don't transfer via the JSON constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }
        
        @Test
        public void equalsPrivateKey() throws MslEncodingException, MslKeyExchangeException, MslException, MslEncoderException {
            final RequestData dataA = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final RequestData dataB = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, RESPONSE_PRIVATE_KEY);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));
            
            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());
            
            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());
            
            // The private keys don't transfer via the JSON constructor.
            assertFalse(dataA.equals(dataA2));
            assertFalse(dataA2.equals(dataA));
            assertTrue(dataA.hashCode() != dataA2.hashCode());
        }
        
        @Test
        public void equalsObject() {
            final RequestData data = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            assertFalse(data.equals(null));
            assertFalse(data.equals(PARAMETERS_ID));
            assertTrue(data.hashCode() != PARAMETERS_ID.hashCode());
        }
    }
    
    /** Response data unit tests. */
    public static class ResponseDataTest {
        /** Key master token. */
        private static final String KEY_MASTER_TOKEN = "mastertoken";
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctors() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            final ResponseData resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            assertEquals(KeyExchangeScheme.DIFFIE_HELLMAN, resp.getKeyExchangeScheme());
            assertEquals(PARAMETERS_ID, resp.getParametersId());
            assertEquals(RESPONSE_PUBLIC_KEY, resp.getPublicKey());
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);
            
            final ResponseData moResp = new ResponseData(MASTER_TOKEN, keydata);
            assertEquals(resp.getKeyExchangeScheme(), moResp.getKeyExchangeScheme());
            assertEquals(resp.getMasterToken(), moResp.getMasterToken());
            assertEquals(resp.getParametersId(), moResp.getParametersId());
            assertEquals(resp.getPublicKey(), moResp.getPublicKey());
            final MslObject moKeydata = moResp.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }
        
        @Test
        public void mslObject() throws MslException, MslEncodingException, MslCryptoException, MslException, MslEncoderException {
            final ResponseData resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, resp);
            assertEquals(KeyExchangeScheme.DIFFIE_HELLMAN.toString(), mo.getString(KEY_SCHEME));
            final MasterToken masterToken = new MasterToken(ctx, mo.getMslObject(KEY_MASTER_TOKEN, encoder));
            assertEquals(MASTER_TOKEN, masterToken);
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            assertEquals(PARAMETERS_ID, keydata.getString(KEY_PARAMETERS_ID));
            assertArrayEquals(prependNullByte(RESPONSE_PUBLIC_KEY.toByteArray()), keydata.getBytes(KEY_PUBLIC_KEY));
        }
        
        @Test
        public void create() throws MslException, MslException, MslEncoderException {
            final ResponseData data = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, data);
            final KeyResponseData keyResponseData = KeyResponseData.create(ctx, mo);
            assertNotNull(keyResponseData);
            assertTrue(keyResponseData instanceof ResponseData);
            
            final ResponseData moData = (ResponseData)keyResponseData;
            assertEquals(data.getKeyExchangeScheme(), moData.getKeyExchangeScheme());
            assertEquals(data.getMasterToken(), moData.getMasterToken());
            assertEquals(data.getParametersId(), moData.getParametersId());
            assertEquals(data.getPublicKey(), moData.getPublicKey());
        }
        
        @Test
        public void missingParametersId() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_PARAMETERS_ID));
            
            new ResponseData(MASTER_TOKEN, keydata);
        }
        
        @Test
        public void missingPublicKey() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_PUBLIC_KEY));
            
            new ResponseData(MASTER_TOKEN, keydata);
        }

        @Test
        public void invalidPublicKey() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_INVALID_PUBLIC_KEY);

            final ResponseData resp = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            
            keydata.put(KEY_PUBLIC_KEY, new byte[0]);
            
            new ResponseData(MASTER_TOKEN, keydata);
        }
        
        @Test
        public void equalsMasterToken() throws MslEncodingException, MslKeyExchangeException, MslException, MslCryptoException, MslEncoderException {
            final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
            final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
            final ResponseData dataA = new ResponseData(masterTokenA, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            final ResponseData dataB = new ResponseData(masterTokenB, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
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
        public void equalsParametersId() throws MslEncodingException, MslKeyExchangeException, MslException, MslEncoderException {
            final ResponseData dataA = new ResponseData(MASTER_TOKEN, PARAMETERS_ID + "A", RESPONSE_PUBLIC_KEY);
            final ResponseData dataB = new ResponseData(MASTER_TOKEN, PARAMETERS_ID + "B", RESPONSE_PUBLIC_KEY);
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
        public void equalsPublicKey() throws MslEncodingException, MslKeyExchangeException, MslException, MslEncoderException {
            final ResponseData dataA = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            final ResponseData dataB = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, REQUEST_PUBLIC_KEY);
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
            final ResponseData data = new ResponseData(MASTER_TOKEN, PARAMETERS_ID, RESPONSE_PUBLIC_KEY);
            assertFalse(data.equals(null));
            assertFalse(data.equals(PARAMETERS_ID));
            assertTrue(data.hashCode() != PARAMETERS_ID.hashCode());
        }
    }
    
    /** Key exchange factory unit tests. */
        public static class KeyExchangeFactoryTest {
        /**
         * Fake key request data for the Diffie-Hellman key exchange scheme.
         */
        private static class FakeKeyRequestData extends KeyRequestData {
            /** Create a new fake key request data. */
            protected FakeKeyRequestData() {
                super(KeyExchangeScheme.DIFFIE_HELLMAN);
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
         * Fake key response data for the Diffie-Hellman key exchange scheme.
         */
        private static class FakeKeyResponseData extends KeyResponseData {
            /** Create a new fake key response data. */
            protected FakeKeyResponseData() {
                super(MASTER_TOKEN, KeyExchangeScheme.DIFFIE_HELLMAN);
            }

            /* (non-Javadoc)
             * @see com.netflix.msl.keyx.KeyResponseData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
             */
            @Override
            protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
                return null;
            }
        }
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @BeforeClass
        public static void setup() {
            authutils = new MockAuthenticationUtils();
            final DiffieHellmanParameters params = MockDiffieHellmanParameters.getDefaultParameters();
            factory = new DiffieHellmanExchange(params, authutils);
            entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
        }
        
        @AfterClass
        public static void teardown() {
        	entityAuthData = null;
            factory = null;
            authutils = null;
        }
        
        @Before
        public void reset() {
            authutils.reset();
            ctx.getMslStore().clearCryptoContexts();
            ctx.getMslStore().clearServiceTokens();
        }
        
        @Test
        public void factory() {
            assertEquals(KeyExchangeScheme.DIFFIE_HELLMAN, factory.getScheme());
        }
        
        @Test
        public void generateInitialResponse() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.DIFFIE_HELLMAN, keyResponseData.getKeyExchangeScheme());
            final MasterToken masterToken = keyResponseData.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(MockPresharedAuthenticationFactory.PSK_ESN, masterToken.getIdentity());
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestInitialResponse() throws MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        }
        
        @Test
        public void invalidParametersIdInitialResponse() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNKNOWN_KEYX_PARAMETERS_ID);

            final KeyRequestData keyRequestData = new RequestData("x", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        }
        
        @Test
        public void unknownParametersIdInitialResponse() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNKNOWN_KEYX_PARAMETERS_ID);

            final KeyRequestData keyRequestData = new RequestData(Integer.toString(98765), REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        }
        
        @Test
        public void generateSubsequentResponse() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.DIFFIE_HELLMAN, keyResponseData.getKeyExchangeScheme());
            final MasterToken masterToken = keyResponseData.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(MASTER_TOKEN.getIdentity(), masterToken.getIdentity());
            assertEquals(MASTER_TOKEN.getSerialNumber(), masterToken.getSerialNumber());
            assertEquals(MASTER_TOKEN.getSequenceNumber() + 1, masterToken.getSequenceNumber());
        }
        
        @Test
        public void untrustedMasterTokenSubsequentResponse() throws MslEncodingException, MslCryptoException, MslException, MslException, MslEncoderException {
            thrown.expect(MslMasterTokenException.class);
            thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);

            final KeyRequestData keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final MasterToken masterToken = MslTestUtils.getUntrustedMasterToken(ctx);
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, masterToken);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestSubsequentResponse() throws MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
        }
        
        @Test
        public void invalidParametersIdSubsequentResponse() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNKNOWN_KEYX_PARAMETERS_ID);

            final KeyRequestData keyRequestData = new RequestData("x", REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
        }
        
        @Test
        public void unknownParametersIdSubsequentResponse() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNKNOWN_KEYX_PARAMETERS_ID);

            final KeyRequestData keyRequestData = new RequestData(Integer.toString(98765), REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, MASTER_TOKEN);
        }
        
        @Test
        public void getCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
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
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            
            final KeyRequestData fakeKeyRequestData = new FakeKeyRequestData();
            factory.getCryptoContext(ctx, fakeKeyRequestData, keyResponseData, null);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongResponseCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
            final KeyRequestData keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final KeyResponseData fakeKeyResponseData = new FakeKeyResponseData();
            factory.getCryptoContext(ctx, keyRequestData, fakeKeyResponseData, null);
        }
        
        @Test
        public void parametersIdMismatchCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_RESPONSE_REQUEST_MISMATCH);

            final KeyRequestData keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, REQUEST_PRIVATE_KEY);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();
            
            final KeyResponseData mismatchedKeyResponseData = new ResponseData(masterToken, PARAMETERS_ID + "x", RESPONSE_PUBLIC_KEY);
            
            factory.getCryptoContext(ctx, keyRequestData, mismatchedKeyResponseData, null);
        }
        
        @Test
        public void privateKeyMissingCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_PRIVATE_KEY_MISSING);

            final KeyRequestData keyRequestData = new RequestData(PARAMETERS_ID, REQUEST_PUBLIC_KEY, null);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            
            factory.getCryptoContext(ctx, keyRequestData, keyResponseData, null);
        }
        
        /** Authentication utilities. */
        private static MockAuthenticationUtils authutils;
        /** Key exchange factory. */
        private static KeyExchangeFactory factory;
        /** Entity authentication data. */
        private static EntityAuthenticationData entityAuthData;
    }
}
