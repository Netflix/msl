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
import javax.xml.bind.DatatypeConverter;

import org.json.JSONException;
import org.json.JSONObject;
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
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.keyx.SymmetricWrappedExchange.KeyId;
import com.netflix.msl.keyx.SymmetricWrappedExchange.RequestData;
import com.netflix.msl.keyx.SymmetricWrappedExchange.ResponseData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.JsonUtils;
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
    /** JSON key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key key request data. */
    private static final String KEY_KEYDATA = "keydata";
    /** JSON key identity. */
    private static final String KEY_IDENTITY = "identity";
    
    /** JSON key symmetric key ID. */
    private static final String KEY_KEY_ID = "keyid";
    /** JSON key wrapped encryption key. */
    private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
    /** JSON key wrapped HMAC key. */
    private static final String KEY_HMAC_KEY = "hmackey";

    private static MasterToken PSK_MASTER_TOKEN;
    private static String PSK_IDENTITY;
    private static final byte[] ENCRYPTION_KEY = new byte[16];
    private static final byte[] HMAC_KEY = new byte[32];

    /** Random. */
    private static Random random;
    /** Preshared keys entity context. */
    private static MslContext pskCtx;
    /** Unauthenticated (server) entity context. */
    private static MslContext unauthCtx;
    
    @BeforeClass
    public static synchronized void setup() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, MslEncodingException, MslCryptoException {
        if (random == null) {
            random = new Random();
            pskCtx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            PSK_MASTER_TOKEN = MslTestUtils.getMasterToken(pskCtx, 1, 1);
            PSK_IDENTITY = PSK_MASTER_TOKEN.getIdentity();
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
        public void ctorsPsk() throws JSONException, MslEncodingException, MslKeyExchangeException {
            final RequestData req = new RequestData(KeyId.PSK);
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, req.getKeyExchangeScheme());
            assertEquals(KeyId.PSK, req.getKeyId());
            final JSONObject keydata = req.getKeydata();
            assertNotNull(keydata);

            final RequestData joReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), joReq.getKeyExchangeScheme());
            assertEquals(req.getKeyId(), joReq.getKeyId());
            final JSONObject joKeydata = joReq.getKeydata();
            assertNotNull(joKeydata);
            assertTrue(JsonUtils.equals(keydata, joKeydata));
        }
        
        @Test
        public void ctorsSession() throws JSONException, MslEncodingException, MslKeyExchangeException {
            final RequestData req = new RequestData(KeyId.SESSION);
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, req.getKeyExchangeScheme());
            assertEquals(KeyId.SESSION, req.getKeyId());
            final JSONObject keydata = req.getKeydata();
            assertNotNull(keydata);

            final RequestData joReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), joReq.getKeyExchangeScheme());
            assertEquals(req.getKeyId(), joReq.getKeyId());
            final JSONObject joKeydata = joReq.getKeydata();
            assertNotNull(joKeydata);
            assertTrue(JsonUtils.equals(keydata, joKeydata));
        }
        
        @Test
        public void jsonString() throws JSONException {
            final RequestData req = new RequestData(KeyId.PSK);
            final JSONObject jo = new JSONObject(req.toJSONString());
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED.toString(), jo.getString(KEY_SCHEME));
            final JSONObject keydata = jo.getJSONObject(KEY_KEYDATA);
            assertEquals(KeyId.PSK.toString(), keydata.getString(KEY_KEY_ID));
        }
        
        @Test
        public void create() throws JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslCryptoException {
            final RequestData data = new RequestData(KeyId.PSK);
            final String jsonString = data.toJSONString();
            final JSONObject jo = new JSONObject(jsonString);
            final KeyRequestData keyRequestData = KeyRequestData.create(pskCtx, jo);
            assertNotNull(keyRequestData);
            assertTrue(keyRequestData instanceof RequestData);
            
            final RequestData joData = (RequestData)keyRequestData;
            assertEquals(data.getKeyExchangeScheme(), joData.getKeyExchangeScheme());
            assertEquals(data.getKeyId(), joData.getKeyId());
        }

        @Test
        public void missingKeyId() throws JSONException, MslEncodingException, MslKeyExchangeException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final RequestData req = new RequestData(KeyId.PSK);
            final JSONObject keydata = req.getKeydata();

            assertNotNull(keydata.remove(KEY_KEY_ID));

            new RequestData(keydata);
        }

        @Test
        public void invalidKeyId() throws JSONException, MslEncodingException, MslCryptoException, MslKeyExchangeException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNIDENTIFIED_KEYX_KEY_ID);

            final RequestData req = new RequestData(KeyId.PSK);
            final JSONObject keydata = req.getKeydata();

            keydata.put(KEY_KEY_ID, "x");

            new RequestData(keydata);
        }
        
        @Test
        public void equalsKeyId() throws MslEncodingException, MslKeyExchangeException, JSONException {
            final RequestData dataA = new RequestData(KeyId.PSK);
            final RequestData dataB = new RequestData(KeyId.SESSION);
            final RequestData dataA2 = new RequestData(dataA.getKeydata());
            
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
        /** JSON key master token. */
        private static final String KEY_MASTER_TOKEN = "mastertoken";
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctors() throws JSONException, MslEncodingException, MslKeyExchangeException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            assertArrayEquals(ENCRYPTION_KEY, resp.getEncryptionKey());
            assertArrayEquals(HMAC_KEY, resp.getHmacKey());
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED, resp.getKeyExchangeScheme());
            assertEquals(KeyId.PSK, resp.getKeyId());
            assertEquals(PSK_MASTER_TOKEN, resp.getMasterToken());
            assertEquals(PSK_IDENTITY, resp.getIdentity());
            final JSONObject keydata = resp.getKeydata();
            assertNotNull(keydata);

            final ResponseData joResp = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, keydata);
            assertArrayEquals(resp.getEncryptionKey(), joResp.getEncryptionKey());
            assertArrayEquals(resp.getHmacKey(), joResp.getHmacKey());
            assertEquals(resp.getKeyExchangeScheme(), joResp.getKeyExchangeScheme());
            assertEquals(resp.getKeyId(), joResp.getKeyId());
            assertEquals(resp.getMasterToken(), joResp.getMasterToken());
            assertEquals(resp.getIdentity(), joResp.getIdentity());
            final JSONObject joKeydata = resp.getKeydata();
            assertNotNull(joKeydata);
            assertTrue(JsonUtils.equals(keydata, joKeydata));
        }

        @Test
        public void jsonString() throws JSONException, MslEncodingException, MslCryptoException, MslException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final JSONObject jo = new JSONObject(resp.toJSONString());
            assertEquals(KeyExchangeScheme.SYMMETRIC_WRAPPED.toString(), jo.getString(KEY_SCHEME));
            final MasterToken masterToken = new MasterToken(pskCtx, jo.getJSONObject(KEY_MASTER_TOKEN));
            assertEquals(PSK_MASTER_TOKEN, masterToken);
            assertEquals(PSK_IDENTITY, jo.getString(KEY_IDENTITY));
            final JSONObject keydata = jo.getJSONObject(KEY_KEYDATA);
            assertEquals(KeyId.PSK.toString(), keydata.getString(KEY_KEY_ID));
            assertArrayEquals(ENCRYPTION_KEY, DatatypeConverter.parseBase64Binary(keydata.getString(KEY_ENCRYPTION_KEY)));
            assertArrayEquals(HMAC_KEY, DatatypeConverter.parseBase64Binary(keydata.getString(KEY_HMAC_KEY)));
        }
        
        @Test
        public void create() throws JSONException, MslException {
            final ResponseData data = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final String jsonString = data.toJSONString();
            final JSONObject jo = new JSONObject(jsonString);
            final KeyResponseData keyResponseData = KeyResponseData.create(pskCtx, jo);
            assertNotNull(keyResponseData);
            assertTrue(keyResponseData instanceof ResponseData);
            
            final ResponseData joData = (ResponseData)keyResponseData;
            assertArrayEquals(data.getEncryptionKey(), joData.getEncryptionKey());
            assertArrayEquals(data.getHmacKey(), joData.getHmacKey());
            assertEquals(data.getKeyExchangeScheme(), joData.getKeyExchangeScheme());
            assertEquals(data.getKeyId(), joData.getKeyId());
            assertEquals(data.getMasterToken(), joData.getMasterToken());
            assertEquals(data.getIdentity(), joData.getIdentity());
        }

        @Test
        public void missingKeyId() throws MslEncodingException, JSONException, MslKeyExchangeException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final JSONObject keydata = resp.getKeydata();

            assertNotNull(keydata.remove(KEY_KEY_ID));

            new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, keydata);
        }

        @Test
        public void missingEncryptionKey() throws JSONException, MslEncodingException, MslKeyExchangeException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final JSONObject keydata = resp.getKeydata();

            assertNotNull(keydata.remove(KEY_ENCRYPTION_KEY));

            new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, keydata);
        }

        @Test
        public void missingHmacKey() throws JSONException, MslEncodingException, MslKeyExchangeException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final JSONObject keydata = resp.getKeydata();

            assertNotNull(keydata.remove(KEY_HMAC_KEY));

            new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, keydata);
        }
        
        @Test
        public void equalsMasterToken() throws MslEncodingException, MslCryptoException, MslKeyExchangeException, JSONException {
            final MasterToken masterTokenA = MslTestUtils.getMasterToken(pskCtx, 1, 1);
            final MasterToken masterTokenB = MslTestUtils.getMasterToken(pskCtx, 1, 2);
            final ResponseData dataA = new ResponseData(masterTokenA, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataB = new ResponseData(masterTokenB, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(masterTokenA, PSK_IDENTITY, dataA.getKeydata());
            
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
        public void equalsKeyId() throws MslEncodingException, MslKeyExchangeException, JSONException {
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.SESSION, ENCRYPTION_KEY, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, dataA.getKeydata());
            
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
        public void equalsEncryptionKey() throws MslEncodingException, MslKeyExchangeException, JSONException {
            final byte[] encryptionKeyA = Arrays.copyOf(ENCRYPTION_KEY, ENCRYPTION_KEY.length);
            final byte[] encryptionKeyB = Arrays.copyOf(ENCRYPTION_KEY, ENCRYPTION_KEY.length);
            ++encryptionKeyB[0];
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, encryptionKeyA, HMAC_KEY);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, encryptionKeyB, HMAC_KEY);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, dataA.getKeydata());
            
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
        public void equalsHmacKey() throws MslEncodingException, MslKeyExchangeException, JSONException {
            final byte[] hmacKeyA = Arrays.copyOf(HMAC_KEY, HMAC_KEY.length);
            final byte[] hmacKeyB = Arrays.copyOf(HMAC_KEY, HMAC_KEY.length);
            ++hmacKeyB[0];
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, hmacKeyA);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, hmacKeyB);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, dataA.getKeydata());
            
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
            final ResponseData data = new ResponseData(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyId.PSK, ENCRYPTION_KEY, HMAC_KEY);
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
             * @see com.netflix.msl.keyx.KeyRequestData#getKeydata()
             */
            @Override
            protected JSONObject getKeydata() throws JSONException {
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
                super(PSK_MASTER_TOKEN, PSK_IDENTITY, KeyExchangeScheme.SYMMETRIC_WRAPPED);
            }

            /* (non-Javadoc)
             * @see com.netflix.msl.keyx.KeyResponseData#getKeydata()
             */
            @Override
            protected JSONObject getKeydata() {
                return null;
            }
        }
        
        /**
         * @param ctx MSL context.
         * @param identity entity identity.
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
        private static MasterToken getUntrustedMasterToken(final MslContext ctx, final String identity, final SecretKey encryptionKey, final SecretKey hmacKey) throws MslEncodingException, MslCryptoException, JSONException, MslException {
            final Date renewalWindow = new Date(System.currentTimeMillis() + 1000);
            final Date expiration = new Date(System.currentTimeMillis() + 2000);
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
        
        @BeforeClass
        public static void setup() {
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
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, entityAuthData);
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
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN);
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
            factory.generateResponse(unauthCtx, keyRequestData, entityAuthData);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestInitialResponse() throws MslInternalException, MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(unauthCtx, keyRequestData, entityAuthData);
        }
        
        @Test
        public void generatePskSubsequentResponse() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN);
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
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN);
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
        public void untrustedMasterTokenPskSubsequentResponse() throws MslInternalException, JSONException, MslException {
            thrown.expect(MslMasterTokenException.class);
            thrown.expectMslError(MslError.MASTERTOKEN_UNTRUSTED);

            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
            final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
            final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
            final MasterToken masterToken = getUntrustedMasterToken(unauthCtx, identity, encryptionKey, hmacKey);
            factory.generateResponse(unauthCtx, keyRequestData, masterToken);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestSubsequentResponse() throws MslInternalException, MslException {
            final KeyRequestData keyRequestData = new FakeKeyRequestData();
            factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN);
        }
        
        @Test(expected = MslMasterTokenException.class)
        public void untrustedMasterTokenSubsequentResponse() throws MslEncodingException, MslCryptoException, JSONException, MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.SESSION);
            final String identity = MockPresharedAuthenticationFactory.PSK_ESN;
            final SecretKey encryptionKey = MockPresharedAuthenticationFactory.KPE;
            final SecretKey hmacKey = MockPresharedAuthenticationFactory.KPH;
            final MasterToken masterToken = getUntrustedMasterToken(unauthCtx, identity, encryptionKey, hmacKey);
            factory.generateResponse(unauthCtx, keyRequestData, masterToken);
        }
        
        @Test
        public void getPskCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, entityAuthData);
            final ICryptoContext requestCryptoContext = keyxData.cryptoContext;
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final ICryptoContext responseCryptoContext = factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, null);
            assertNotNull(responseCryptoContext);
            
            final byte[] data = new byte[32];
            random.nextBytes(data);

            // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            final byte[] requestCiphertext = requestCryptoContext.encrypt(data);
            final byte[] responseCiphertext = responseCryptoContext.encrypt(data);
            assertFalse(Arrays.equals(data, requestCiphertext));
            assertFalse(Arrays.equals(data, responseCiphertext));

            // Signatures should always be equal.
            final byte[] requestSignature = requestCryptoContext.sign(data);
            final byte[] responseSignature = responseCryptoContext.sign(data);
            assertFalse(Arrays.equals(data, requestSignature));
            assertFalse(Arrays.equals(data, responseSignature));
            assertArrayEquals(requestSignature, responseSignature);

            // Plaintext should always be equal to the original message.
            final byte[] requestPlaintext = requestCryptoContext.decrypt(responseCiphertext);
            final byte[] responsePlaintext = responseCryptoContext.decrypt(requestCiphertext);
            assertNotNull(requestPlaintext);
            assertArrayEquals(data, requestPlaintext);
            assertArrayEquals(requestPlaintext, responsePlaintext);

            // Verification should always succeed.
            assertTrue(requestCryptoContext.verify(data, responseSignature));
            assertTrue(responseCryptoContext.verify(data, requestSignature));
        }
        
        @Ignore
        @Test
        public void getSessionCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.SESSION);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN);
            final ICryptoContext requestCryptoContext = keyxData.cryptoContext;
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final ICryptoContext responseCryptoContext = factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, PSK_MASTER_TOKEN);
            assertNotNull(responseCryptoContext);
            
            final byte[] data = new byte[32];
            random.nextBytes(data);
            
            final byte[] requestCiphertext = requestCryptoContext.encrypt(data);
            final byte[] responseCiphertext = responseCryptoContext.encrypt(data);
            assertFalse(Arrays.equals(data, requestCiphertext));
            assertFalse(Arrays.equals(data, responseCiphertext));
            
            final byte[] requestSignature = requestCryptoContext.sign(data);
            final byte[] responseSignature = responseCryptoContext.sign(data);
            assertFalse(Arrays.equals(data, requestSignature));
            assertFalse(Arrays.equals(data, responseSignature));
            
            final byte[] requestPlaintext = requestCryptoContext.decrypt(responseCiphertext);
            final byte[] responsePlaintext = responseCryptoContext.decrypt(requestCiphertext);
            assertNotNull(requestPlaintext);
            assertArrayEquals(data, requestPlaintext);
            assertArrayEquals(requestPlaintext, responsePlaintext);
            
            assertTrue(requestCryptoContext.verify(data, responseSignature));
            assertTrue(responseCryptoContext.verify(data, requestSignature));
        }
        
        @Ignore
        @Test
        public void missingMasterTokenCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_MASTER_TOKEN_MISSING);

            final KeyRequestData keyRequestData = new RequestData(KeyId.SESSION);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, PSK_MASTER_TOKEN);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            factory.getCryptoContext(pskCtx, keyRequestData, keyResponseData, null);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestCryptoContext() throws MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, entityAuthData);
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
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();
            
            final KeyResponseData mismatchedKeyResponseData = new ResponseData(masterToken, PSK_IDENTITY, KeyId.SESSION, ENCRYPTION_KEY, HMAC_KEY);
            
            factory.getCryptoContext(pskCtx, keyRequestData, mismatchedKeyResponseData, null);
        }
        
        @Test(expected = MslCryptoException.class)
        public void invalidWrappedEncryptionKeyCryptoContext() throws JSONException, MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();
            
            final JSONObject keydata = keyResponseData.getKeydata();
            final byte[] wrappedEncryptionKey = DatatypeConverter.parseBase64Binary(keydata.getString(KEY_ENCRYPTION_KEY));
            ++wrappedEncryptionKey[wrappedEncryptionKey.length-1];
            keydata.put(KEY_ENCRYPTION_KEY, DatatypeConverter.printBase64Binary(wrappedEncryptionKey));
            final byte[] wrappedHmacKey = DatatypeConverter.parseBase64Binary(keydata.getString(KEY_HMAC_KEY));
            
            final KeyResponseData invalidKeyResponseData = new ResponseData(masterToken, PSK_IDENTITY, KeyId.PSK, wrappedEncryptionKey, wrappedHmacKey);
            factory.getCryptoContext(pskCtx, keyRequestData, invalidKeyResponseData, null);
        }
        
        @Test(expected = MslCryptoException.class)
        public void invalidWrappedHmacKeyCryptoContext() throws JSONException, MslException {
            final KeyRequestData keyRequestData = new RequestData(KeyId.PSK);
            final KeyExchangeData keyxData = factory.generateResponse(unauthCtx, keyRequestData, entityAuthData);
            final KeyResponseData keyResponseData = keyxData.keyResponseData;
            final MasterToken masterToken = keyResponseData.getMasterToken();
            
            final JSONObject keydata = keyResponseData.getKeydata();
            final byte[] wrappedHmacKey = DatatypeConverter.parseBase64Binary(keydata.getString(KEY_HMAC_KEY));
            ++wrappedHmacKey[wrappedHmacKey.length-1];
            keydata.put(KEY_HMAC_KEY, DatatypeConverter.printBase64Binary(wrappedHmacKey));
            final byte[] wrappedEncryptionKey = DatatypeConverter.parseBase64Binary(keydata.getString(KEY_ENCRYPTION_KEY));
            
            final KeyResponseData invalidKeyResponseData = new ResponseData(masterToken, PSK_IDENTITY, KeyId.PSK, wrappedEncryptionKey, wrappedHmacKey);
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
