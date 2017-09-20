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
import static org.junit.Assert.assertTrue;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import javax.crypto.SecretKey;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
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
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.keyx.SymmetricWrappedExchange.KeyId;
import com.netflix.msl.keyx.SymmetricWrappedExchange.RequestData;
import com.netflix.msl.keyx.SymmetricWrappedExchange.ResponseData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Symmetric wrapped key exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({SymmetricWrappedExchangeSuite.KeyExchangeFactoryTest.class,
               SymmetricWrappedExchangeSuite.RequestDataTest.class,
               SymmetricWrappedExchangeSuite.ResponseDataTest.class})
public class SymmetricWrappedExchangeSuite {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key key request data. */
    private static final String KEY_KEYDATA = "keydata";
    
    /** Key symmetric key ID. */
    private static final String KEY_KEY_ID = "keyid";
    /** Key wrapped encryption key. */
    private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
    /** Key wrapped HMAC key. */
    private static final String KEY_HMAC_KEY = "hmackey";

    private static MasterToken PSK_MASTER_TOKEN;
    private static final byte[] ENCRYPTION_KEY = new byte[16];
    private static final byte[] HMAC_KEY = new byte[32];

    /** Random. */
    private static Random random;
    /** Preshared keys entity context. */
    private static MslContext pskCtx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Unauthenticated (server) entity context. */
    private static MslContext unauthCtx;
    
    @BeforeClass
    public static synchronized void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslEncodingException, MslCryptoException {
        if (random == null) {
            random = new Random();
            pskCtx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            encoder = pskCtx.getMslEncoderFactory();
            PSK_MASTER_TOKEN = MslTestUtils.getMasterToken(pskCtx, 1, 1);
            unauthCtx = new MockMslContext(EntityAuthenticationScheme.NONE, false);
            random.nextBytes(ENCRYPTION_KEY);
            random.nextBytes(HMAC_KEY);
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
        public void ctorsPsk() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            final RequestData req = new RequestData(KeyId.PSK);
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, req.getKeyExchangeScheme());
            assertEquals(KeyId.PSK, req.getKeyId());
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);

            final RequestData moReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
            assertEquals(req.getKeyId(), moReq.getKeyId());
            final MslObject moKeydata = moReq.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }
        
        @Test
        public void ctorsSession() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            final RequestData req = new RequestData(KeyId.SESSION);
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, req.getKeyExchangeScheme());
            assertEquals(KeyId.SESSION, req.getKeyId());
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);

            final RequestData moReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
            assertEquals(req.getKeyId(), moReq.getKeyId());
            final MslObject moKeydata = moReq.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }
        
        @Test
        public void mslObject() throws MslException, MslEncoderException {
            final RequestData req = new RequestData(KeyId.PSK);
            final MslObject mo = MslTestUtils.toMslObject(encoder, req);
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED.toString(), mo.getString(KEY_SCHEME));
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            assertEquals(KeyId.PSK.toString(), keydata.getString(KEY_KEY_ID));
        }
        
        @Test
        public void create() throws MslException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslCryptoException, MslEncoderException {
            final RequestData data = new RequestData(KeyId.PSK);
            final MslObject mo = MslTestUtils.toMslObject(encoder, data);
            final KeyRequestData keyRequestData = KeyRequestData.create(pskCtx, mo);
            assertNotNull(keyRequestData);
            assertTrue(keyRequestData instanceof RequestData);
            
            final RequestData moData = (RequestData)keyRequestData;
            assertEquals(data.getKeyExchangeScheme(), moData.getKeyExchangeScheme());
            assertEquals(data.getKeyId(), moData.getKeyId());
        }

        @Test
        public void missingKeyId() throws MslException, MslEncodingException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final RequestData req = new RequestData(KeyId.PSK);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);

            assertNotNull(keydata.remove(KEY_KEY_ID));

            new RequestData(keydata);
        }

        @Test
        public void invalidKeyId() throws MslException, MslEncodingException, MslCryptoException, MslKeyExchangeException, MslEncoderException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNIDENTIFIED_KEYX_KEY_ID);

            final RequestData req = new RequestData(KeyId.PSK);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);

            keydata.put(KEY_KEY_ID, "x");

            new RequestData(keydata);
        }
        
        @Test
        public void equalsKeyId() throws MslEncodingException, MslKeyExchangeException, MslException, MslEncoderException {
            final RequestData dataA = new RequestData(KeyId.PSK);
            final RequestData dataB = new RequestData(KeyId.SESSION);
            final RequestData dataA2 = new RequestData(dataA.getKeydata(encoder, ENCODER_FORMAT));
            
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
            final RequestData data = new RequestData(KeyId.PSK);
            assertFalse(data.equals(null));
            assertFalse(data.equals(KEY_KEY_ID));
            assertTrue(data.hashCode() != KEY_KEY_ID.hashCode());
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
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            assertArrayEquals(ENCRYPTION_KEY, resp.getEncryptionKey());
            assertArrayEquals(HMAC_KEY, resp.getHmacKey());
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, resp.getKeyExchangeScheme());
            assertEquals(KeyId.PSK, resp.getKeyId());
            assertEquals(PSK_MASTER_TOKEN, resp.getMasterToken());
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);

            final ResponseData moResp = new ResponseData(PSK_MASTER_TOKEN, keydata);
            assertArrayEquals(resp.getEncryptionKey(), moResp.getEncryptionKey());
            assertArrayEquals(resp.getHmacKey(), moResp.getHmacKey());
            assertEquals(resp.getKeyExchangeScheme(), moResp.getKeyExchangeScheme());
            assertEquals(resp.getKeyId(), moResp.getKeyId());
            assertEquals(resp.getMasterToken(), moResp.getMasterToken());
            final MslObject moKeydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }

        @Test
        public void mslObject() throws MslException, MslEncodingException, MslCryptoException, MslException, MslEncoderException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, resp);
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED.toString(), mo.getString(KEY_SCHEME));
            final MasterToken masterToken = new MasterToken(pskCtx, mo.getMslObject(KEY_MASTER_TOKEN, encoder));
            assertEquals(PSK_MASTER_TOKEN, masterToken);
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            assertEquals(KeyId.PSK.toString(), keydata.getString(KEY_KEY_ID));
            assertArrayEquals(ENCRYPTION_KEY, keydata.getBytes(KEY_ENCRYPTION_KEY));
            assertArrayEquals(HMAC_KEY, keydata.getBytes(KEY_HMAC_KEY));
        }
        
        @Test
        public void create() throws MslException, MslException, MslEncoderException {
            final ResponseData data = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject mo = MslTestUtils.toMslObject(encoder, data);
            final KeyResponseData keyResponseData = KeyResponseData.create(pskCtx, mo);
            assertNotNull(keyResponseData);
            assertTrue(keyResponseData instanceof ResponseData);
            
            final ResponseData moData = (ResponseData)keyResponseData;
            assertArrayEquals(data.getEncryptionKey(), moData.getEncryptionKey());
            assertArrayEquals(data.getHmacKey(), moData.getHmacKey());
            assertEquals(data.getKeyExchangeScheme(), moData.getKeyExchangeScheme());
            assertEquals(data.getKeyId(), moData.getKeyId());
            assertEquals(data.getMasterToken(), moData.getMasterToken());
        }

        @Test
        public void missingKeyId() throws MslEncodingException, MslException, MslKeyExchangeException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            assertNotNull(keydata.remove(KEY_KEY_ID));

            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }

        @Test
        public void missingEncryptionKey() throws MslException, MslEncodingException, MslKeyExchangeException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            assertNotNull(keydata.remove(KEY_ENCRYPTION_KEY));

            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }

        @Test
        public void missingHmacKey() throws MslException, MslEncodingException, MslKeyExchangeException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);

            assertNotNull(keydata.remove(KEY_HMAC_KEY));

            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void equalsMasterToken() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final MasterToken masterTokenA = MslTestUtils.getMasterToken(pskCtx, 1, 1);
            final MasterToken masterTokenB = MslTestUtils.getMasterToken(pskCtx, 1, 2);
            final ResponseData dataA = new ResponseData(masterTokenA, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataB = new ResponseData(masterTokenB, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
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
        public void equalsKeyId() throws MslEncodingException, MslKeyExchangeException, MslException {
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.SESSION, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));
            
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
        public void equalsEncryptionKey() throws MslEncodingException, MslKeyExchangeException, MslException {
            final byte[] encryptionKeyA = Arrays.copyOf(ENCRYPTION_KEY, ENCRYPTION_KEY.length);
            final byte[] encryptionKeyB = Arrays.copyOf(ENCRYPTION_KEY, ENCRYPTION_KEY.length);
            ++encryptionKeyB[0];
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, encryptionKeyA, HMAC_KEY);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, encryptionKeyB, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));
            
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
        public void equalsHmacKey() throws MslEncodingException, MslKeyExchangeException, MslException {
            final byte[] hmacKeyA = Arrays.copyOf(HMAC_KEY, HMAC_KEY.length);
            final byte[] hmacKeyB = Arrays.copyOf(HMAC_KEY, HMAC_KEY.length);
            ++hmacKeyB[0];
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, hmacKeyA);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, hmacKeyB);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, dataA.getKeydata(encoder, ENCODER_FORMAT));
            
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
            final ResponseData data = new ResponseData(PSK_MASTER_TOKEN, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            assertFalse(data.equals(null));
            assertFalse(data.equals(KEY_KEY_ID));
            assertTrue(data.hashCode() != KEY_KEY_ID.hashCode());
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
                super(KeyExchangeScheme.SYMMETRIC_WRAPPED);
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
                super(PSK_MASTER_TOKEN, KeyExchangeScheme.SYMMETRIC_WRAPPED);
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
         * @param identity entity identity.
         * @param encryptionKey master token encryption key.
         * @param hmacKey master token HMAC key.
         * @return a new master token.
         * @throws MslException if the master token is constructed incorrectly.
         * @throws MslEncoderException if there is an error editing the data.
         */
        private static MasterToken getUntrustedMasterToken(final MslContext ctx, final String identity, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslEncoderException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
            final Date expiration = new Date(System.currentTimeMillis() + 2000);
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
        public static void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslEncodingException, MslCryptoException {
            SymmetricWrappedExchangeSuite.setup();
            
            authutils = new MockAuthenticationUtils();
            factory = new SymmetricWrappedExchange(authutils);
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
            pskCtx.getMslStore().clearCryptoContexts();
            pskCtx.getMslStore().clearServiceTokens();
        }
        
        @Test
        public void factory() {
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, factory.getScheme());
        }
        
        @Test
        public void generatePskInitialResponse() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, keyResponseData.getKeyExchangeScheme());
            final MasterToken masterToken = keyResponseData.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(MockPresharedAuthenticationFactory.PSK_ESN, masterToken.getIdentity());
        }
        
        @Ignore
        @Test
        public void generateSessionInitialResponse() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.SESSION);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, keyResponseData.getKeyExchangeScheme());
            final MasterToken masterToken = keyResponseData.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(PSK_MASTER_TOKEN.getIdentity(), masterToken.getIdentity());
        }
        
        @Test(expected = MslEntityAuthException.class)
        public void invalidPskInitialResponse() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final EntityAuthenticationData entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN + "x");
            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestInitialResponse() throws MslInternalException, MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
        }
        
        @Test
        public void generatePskSubsequentResponse() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, keyResponseData.getKeyExchangeScheme());
            final MasterToken masterToken = keyResponseData.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(PSK_MASTER_TOKEN.getIdentity(), masterToken.getIdentity());
            assertEquals(PSK_MASTER_TOKEN.getSerialNumber(), masterToken.getSerialNumber());
            assertEquals(PSK_MASTER_TOKEN.getSequenceNumber() + 1, masterToken.getSequenceNumber());
        }

        @Ignore
        @Test
        public void generateSessionSubsequentResponse() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.SESSION);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, keyResponseData.getKeyExchangeScheme());
            final MasterToken masterToken = keyResponseData.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(PSK_MASTER_TOKEN.getIdentity(), masterToken.getIdentity());
            assertEquals(PSK_MASTER_TOKEN.getSerialNumber(), masterToken.getSerialNumber());
            assertEquals(PSK_MASTER_TOKEN.getSequenceNumber() + 1, masterToken.getSequenceNumber());
        }
        
        @Test
        public void untrustedMasterTokenPskSubsequentResponse() throws MslInternalException, MslException, MslException, MslEncoderException {
            thrown.expect(MslMasterTokenException.class);
            thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);

            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
            final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
            final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
            final MasterToken masterToken = getUntrustedMasterToken(unauthCtx, identity, encryptionKey, hmacKey);
            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, masterToken);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestSubsequentResponse() throws MslInternalException, MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
        }
        
        @Test(expected = MslMasterTokenException.class)
        public void untrustedMasterTokenSubsequentResponse() throws MslEncodingException, MslCryptoException, MslException, MslException, MslEncoderException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.SESSION);
            final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
            final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
            final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
            final MasterToken masterToken = getUntrustedMasterToken(unauthCtx, identity, encryptionKey, hmacKey);
            factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, masterToken);
        }
        
        @Test
        public void getPskCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final ICryptoContext requestCryptoContext = keyxData.cryptoContext;
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final ICryptoContext responseCryptoContext = factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, null);
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
        
        @Ignore
        @Test
        public void getSessionCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.SESSION);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
            final ICryptoContext requestCryptoContext = keyxData.cryptoContext;
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final ICryptoContext responseCryptoContext = factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, PSK_MASTER_TOKEN);
            assertNotNull(responseCryptoContext);
            
            final byte[] data = new byte[32];
            random.nextBytes(data);
            
            final byte[] requestCiphertext = requestCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
            final byte[] responseCiphertext = responseCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
            assertFalse(Arrays.equals(data, requestCiphertext));
            assertFalse(Arrays.equals(data, responseCiphertext));
            
            final byte[] requestSignature = requestCryptoContext.sign(data, encoder, ENCODER_FORMAT);
            final byte[] responseSignature = responseCryptoContext.sign(data, encoder, ENCODER_FORMAT);
            assertFalse(Arrays.equals(data, requestSignature));
            assertFalse(Arrays.equals(data, responseSignature));
            
            final byte[] requestPlaintext = requestCryptoContext.decrypt(responseCiphertext, encoder);
            final byte[] responsePlaintext = responseCryptoContext.decrypt(requestCiphertext, encoder);
            assertNotNull(requestPlaintext);
            assertArrayEquals(data, requestPlaintext);
            assertArrayEquals(requestPlaintext, responsePlaintext);
            
            assertTrue(requestCryptoContext.verify(data, responseSignature, encoder));
            assertTrue(responseCryptoContext.verify(data, requestSignature, encoder));
        }
        
        @Ignore
        @Test
        public void missingMasterTokenCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_MASTER_TOKEN_MISSING);

            final KeyRequestData keyRequestData = new RequestData(KeyId.SESSION);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, PSK_MASTER_TOKEN);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, null);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            
            final KeyRequestData fakeKeyRequestData = new FakeKeyRequestData();
            factory.getCryptoContext(pskCtx, fakeKeyRequestData, keyResponseData, null);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongResponseCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyResponseData fakeKeyResponseData = new FakeKeyResponseData();
            factory.getCryptoContext(pskCtx, keyRequestData, fakeKeyResponseData, null);
        }
        
        @Test
        public void keyIdMismatchCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_RESPONSE_REQUEST_MISMATCH);

            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();
            
            final KeyResponseData mismatchedKeyResponseData = new ResponseData(masterToken, KeyId.SESSION, ENCRYPTION_KEY, HMAC_KEY);
            
            factory.getCryptoContext(pskCtx, keyRequestData, mismatchedKeyResponseData, null);
        }
        
        @Test(expected = MslCryptoException.class)
        public void invalidWrappedEncryptionKeyCryptoContext() throws MslException, MslException, MslEncoderException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();
            
            final MslObject keydata = keyResponseData.getKeydata(encoder, ENCODER_FORMAT);
            final byte[] wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);
            ++wrappedEncryptionKey[wrappedEncryptionKey.length-1];
            keydata.put(KEY_ENCRYPTION_KEY, wrappedEncryptionKey);
            final byte[] wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);
            
            final KeyResponseData invalidKeyResponseData = new ResponseData(masterToken, KeyId.PSK, wrappedEncryptionKey, wrappedHmacKey);
            factory.getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, null);
        }
        
        @Test(expected = MslCryptoException.class)
        public void invalidWrappedHmacKeyCryptoContext() throws MslException, MslException, MslEncoderException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, ENCODER_FORMAT, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();
            
            final MslObject keydata = keyResponseData.getKeydata(encoder, ENCODER_FORMAT);
            final byte[] wrappedHmacKey = keydata.getBytes(KEY_HMAC_KEY);
            ++wrappedHmacKey[wrappedHmacKey.length-1];
            keydata.put(KEY_HMAC_KEY, wrappedHmacKey);
            final byte[] wrappedEncryptionKey = keydata.getBytes(KEY_ENCRYPTION_KEY);
            
            final KeyResponseData invalidKeyResponseData = new ResponseData(masterToken, KeyId.PSK, wrappedEncryptionKey, wrappedHmacKey);
            factory.getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, null);
        }
        
        /** Authentication utilities. */
        private static MockAuthenticationUtils authutils;
        /** Key exchange factory. */
        private static KeyExchangeFactory factory;
        /** Entity authentication data. */
        private static EntityAuthenticationData entityAuthData;
    }
}
