/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONException;
import org.json.JSONObject;
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
import com.netflix.msl.crypto.JcaAlgorithm;
import com.netflix.msl.crypto.JsonWebKey;
import com.netflix.msl.crypto.JsonWebKey.Algorithm;
import com.netflix.msl.crypto.JsonWebKey.Usage;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.AesKwJwkCryptoContext;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.JwkCryptoContext;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.Mechanism;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.RequestData;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.ResponseData;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.Base64;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * JSON Web Key ladder exchange unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
@RunWith(Suite.class)
@SuiteClasses({JsonWebKeyLadderExchangeSuite.KeyExchangeFactoryTest.class,
               JsonWebKeyLadderExchangeSuite.RequestDataTest.class,
               JsonWebKeyLadderExchangeSuite.ResponseDataTest.class})
public class JsonWebKeyLadderExchangeSuite {
    /** Encoding charset. */
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    /** JSON key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key key request data. */
    private static final String KEY_KEYDATA = "keydata";
    
    private static ICryptoContext PSK_CRYPTO_CONTEXT, WRAP_CRYPTO_CONTEXT;
    private static byte[] WRAP_JWK;
    private static byte[] WRAPDATA;

    private static final String PSK_IDENTITY = MockPresharedAuthenticationFactory.PSK_ESN;
    private static MasterToken PSK_MASTER_TOKEN;
    private static byte[] PSK_ENCRYPTION_JWK;
    private static byte[] PSK_HMAC_JWK;
    
    @BeforeClass
    public static synchronized void setup() throws MslEncodingException, MslCryptoException, NoSuchAlgorithmException, MslEntityAuthException {
        if (pskCtx == null) {
            Security.addProvider(new BouncyCastleProvider());
            
            pskCtx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            
            // Create PSK wrapping crypto context.
            {
                final EntityAuthenticationData entityAuthData = pskCtx.getEntityAuthenticationData(null);
                final EntityAuthenticationFactory entityAuthFactory = pskCtx.getEntityAuthenticationFactory(entityAuthData.getScheme());
                final ICryptoContext cryptoContext = entityAuthFactory.getCryptoContext(pskCtx, entityAuthData);
                PSK_CRYPTO_CONTEXT = new AesKwJwkCryptoContext(cryptoContext);
            }
                        
            // The wrap key is the new wrapping key wrapped by the specified
            // wrapping key (e.g. PSK or RSA) inside a JWK. Technically we
            // shouldn't know this but that's the only way to verify things.
            //
            // Create the new wrapping key and wrap crypto context.
            final byte[] wrappingKey = new byte[16];
            pskCtx.getRandom().nextBytes(wrappingKey);
            final SecretKey wrapKey = new SecretKeySpec(wrappingKey, JcaAlgorithm.AESKW);
            WRAP_CRYPTO_CONTEXT = new AesKwJwkCryptoContext(wrapKey);
            //
            // Wrap the new wrapping key using a PSK wrap crypto context.
            final JsonWebKey wrapJwk = new JsonWebKey(Usage.wrap, Algorithm.A128KW, false, null, wrapKey);
            WRAP_JWK = PSK_CRYPTO_CONTEXT.wrap(wrapJwk.toJSONString().getBytes(UTF_8));
            
            // The wrap data is an AES-128 key wrapped by the primary MSL
            // context. Technically we shouldn't know this but that's the only
            // way to verify things.
            WRAPDATA = pskCtx.getMslCryptoContext().wrap(wrappingKey);

            final WrapCryptoContextRepository repository = new MockCryptoContextRepository();
            final AuthenticationUtils authutils = new MockAuthenticationUtils();
            final KeyExchangeFactory keyxFactory = new JsonWebKeyLadderExchange(repository, authutils);
            pskCtx.addKeyExchangeFactory(keyxFactory);
    
            PSK_MASTER_TOKEN = MslTestUtils.getMasterToken(pskCtx, 1, 1);
            final SecretKey pskEncryptionKey = PSK_MASTER_TOKEN.getEncryptionKey();
            final JsonWebKey pskEncryptionJwk = new JsonWebKey(Usage.enc, Algorithm.A128CBC, false, null, pskEncryptionKey);
            PSK_ENCRYPTION_JWK = WRAP_CRYPTO_CONTEXT.wrap(pskEncryptionJwk.toJSONString().getBytes(UTF_8));
            final SecretKey pskHmacKey = PSK_MASTER_TOKEN.getSignatureKey();
            final JsonWebKey pskHmacJwk = new JsonWebKey(Usage.sig, Algorithm.HS256, false, null, pskHmacKey);
            PSK_HMAC_JWK = WRAP_CRYPTO_CONTEXT.wrap(pskHmacJwk.toJSONString().getBytes(UTF_8));
        }
    }
    
    @AfterClass
    public static synchronized void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }
    
    /** PSK MSL context. */
    private static MockMslContext pskCtx;

    /** Request data unit tests. */
    public static class RequestDataTest {
        /** JSON key wrap key wrapping mechanism. */
        private static final String KEY_MECHANISM = "mechanism";
        /** JSON key public key. */
        private static final String KEY_PUBLIC_KEY = "publickey";
        /** JSON key wrap data. */
        private static final String KEY_WRAPDATA = "wrapdata";
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctorsWrap() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, JSONException {
            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            assertEquals(KeyExchangeScheme.JWK_LADDER, req.getKeyExchangeScheme());
            assertEquals(Mechanism.WRAP, req.getMechanism());
            assertArrayEquals(WRAPDATA, req.getWrapdata());
            final JSONObject keydata = req.getKeydata();
            assertNotNull(keydata);
            
            final RequestData joReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), joReq.getKeyExchangeScheme());
            assertEquals(req.getMechanism(), joReq.getMechanism());
            assertArrayEquals(req.getWrapdata(), joReq.getWrapdata());
            final JSONObject joKeydata = req.getKeydata();
            assertNotNull(joKeydata);
            assertTrue(JsonUtils.equals(keydata, joKeydata));
        }
        
        @Test
        public void jsonWrap() throws JSONException {
            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final JSONObject jo = new JSONObject(req.toJSONString());
            assertEquals(KeyExchangeScheme.JWK_LADDER.name(), jo.getString(KEY_SCHEME));
            final JSONObject keydata = jo.getJSONObject(KEY_KEYDATA);
            assertEquals(Mechanism.WRAP.name(), keydata.getString(KEY_MECHANISM));
            assertFalse(keydata.has(KEY_PUBLIC_KEY));
            assertArrayEquals(WRAPDATA, Base64.decode(keydata.getString(KEY_WRAPDATA)));
        }
        
        @Test
        public void createWrap() throws JSONException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslCryptoException {
            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final JSONObject jo = new JSONObject(req.toJSONString());
            final KeyRequestData keyRequestData = KeyRequestData.create(pskCtx, jo);
            assertNotNull(keyRequestData);
            assertTrue(keyRequestData instanceof RequestData);
            
            final RequestData joReq = (RequestData)keyRequestData;
            assertEquals(req.getKeyExchangeScheme(), joReq.getKeyExchangeScheme());
            assertEquals(req.getMechanism(), joReq.getMechanism());
            assertArrayEquals(req.getWrapdata(), joReq.getWrapdata());
        }
        
        @Test(expected = MslInternalException.class)
        public void ctorWrapNullWrapdata() {
            new RequestData(Mechanism.WRAP, null);
        }
        
        @Test
        public void ctorsPsk() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, JSONException {
            final RequestData req = new RequestData(Mechanism.PSK, null);
            assertEquals(KeyExchangeScheme.JWK_LADDER, req.getKeyExchangeScheme());
            assertEquals(Mechanism.PSK, req.getMechanism());
            assertNull(req.getWrapdata());
            final JSONObject keydata = req.getKeydata();
            assertNotNull(keydata);
            
            final RequestData joReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), joReq.getKeyExchangeScheme());
            assertEquals(req.getMechanism(), joReq.getMechanism());
            assertNull(joReq.getWrapdata());
            final JSONObject joKeydata = req.getKeydata();
            assertNotNull(joKeydata);
            assertTrue(JsonUtils.equals(keydata, joKeydata));
        }
        
        @Test
        public void jsonPsk() throws JSONException {
            final RequestData req = new RequestData(Mechanism.PSK, null);
            final JSONObject jo = new JSONObject(req.toJSONString());
            assertEquals(KeyExchangeScheme.JWK_LADDER.name(), jo.getString(KEY_SCHEME));
            final JSONObject keydata = jo.getJSONObject(KEY_KEYDATA);
            assertEquals(Mechanism.PSK.name(), keydata.getString(KEY_MECHANISM));
            assertFalse(keydata.has(KEY_PUBLIC_KEY));
            assertFalse(keydata.has(KEY_WRAPDATA));
        }
        
        @Test
        public void createPsk() throws MslEncodingException, MslEntityAuthException, MslKeyExchangeException, JSONException, MslCryptoException {
            final RequestData req = new RequestData(Mechanism.PSK, null);
            final JSONObject jo = new JSONObject(req.toJSONString());
            final KeyRequestData keyRequestData = KeyRequestData.create(pskCtx, jo);
            assertNotNull(keyRequestData);
            assertTrue(keyRequestData instanceof RequestData);
            
            final RequestData joReq = (RequestData)keyRequestData;
            assertEquals(req.getKeyExchangeScheme(), joReq.getKeyExchangeScheme());
            assertEquals(req.getMechanism(), joReq.getMechanism());
            assertNull(joReq.getWrapdata());
        }
        
        @Test
        public void missingMechanism() throws JSONException, MslCryptoException, MslKeyExchangeException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final RequestData req = new RequestData(Mechanism.PSK, null);
            final JSONObject keydata = req.getKeydata();
            
            assertNotNull(keydata.remove(KEY_MECHANISM));
            
            new RequestData(keydata);
        }
        
        @Test
        public void invalidMechanism() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, JSONException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNIDENTIFIED_KEYX_MECHANISM);

            final RequestData req = new RequestData(Mechanism.PSK, null);
            final JSONObject keydata = req.getKeydata();
            
            keydata.put(KEY_MECHANISM, "x");
            
            new RequestData(keydata);
        }
        
        @Test
        public void wrapMissingWrapdata() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, JSONException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final JSONObject keydata = req.getKeydata();
            
            assertNotNull(keydata.remove(KEY_WRAPDATA));
            
            new RequestData(keydata);
        }
        
        @Test
        public void wrapInvalidWrapdata() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, JSONException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_INVALID_WRAPDATA);

            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final JSONObject keydata = req.getKeydata();
            
            keydata.put(KEY_WRAPDATA, "x");
            
            new RequestData(keydata);
        }
        
        @Test
        public void equalsMechanism() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, JSONException {
            final RequestData dataA = new RequestData(Mechanism.WRAP, WRAPDATA);
            final RequestData dataB = new RequestData(Mechanism.PSK, null);
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
        public void equalsWrapdata() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, JSONException {
            final byte[] wrapdataB = Arrays.copyOf(WRAPDATA, WRAPDATA.length);
            ++wrapdataB[0];
            
            final RequestData dataA = new RequestData(Mechanism.WRAP, WRAPDATA);
            final RequestData dataB = new RequestData(Mechanism.WRAP, wrapdataB);
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
    }
    
    /** Response data unit tests. */
        public static class ResponseDataTest {
        /** JSON key master token. */
        private static final String KEY_MASTER_TOKEN = "mastertoken";
        
        /** JSON key wrapping key. */
        private static final String KEY_WRAP_KEY = "wrapkey";
        /** JSON key wrapping key data. */
        private static final String KEY_WRAPDATA = "wrapdata";
        /** JSON key encrypted encryption key. */
        private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
        /** JSON key encrypted HMAC key. */
        private static final String KEY_HMAC_KEY = "hmackey";
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctors() throws JSONException, MslKeyExchangeException, MslEncodingException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            assertArrayEquals(PSK_ENCRYPTION_JWK, resp.getEncryptionKey());
            assertArrayEquals(PSK_HMAC_JWK, resp.getHmacKey());
            assertEquals(KeyExchangeScheme.JWK_LADDER, resp.getKeyExchangeScheme());
            assertEquals(PSK_MASTER_TOKEN, resp.getMasterToken());
            assertArrayEquals(WRAPDATA, resp.getWrapdata());
            assertArrayEquals(WRAP_JWK, resp.getWrapKey());
            final JSONObject keydata = resp.getKeydata();
            assertNotNull(keydata);
            
            final ResponseData joResp = new ResponseData(PSK_MASTER_TOKEN, keydata);
            assertArrayEquals(resp.getEncryptionKey(), joResp.getEncryptionKey());
            assertArrayEquals(resp.getHmacKey(), joResp.getHmacKey());
            assertEquals(resp.getKeyExchangeScheme(), joResp.getKeyExchangeScheme());
            assertEquals(resp.getMasterToken(), joResp.getMasterToken());
            assertArrayEquals(resp.getWrapdata(), joResp.getWrapdata());
            assertArrayEquals(resp.getWrapKey(), joResp.getWrapKey());
            final JSONObject joKeydata = joResp.getKeydata();
            assertNotNull(joKeydata);
            assertTrue(JsonUtils.equals(keydata, joKeydata));
        }
        
        @Test
        public void json() throws MslEncodingException, MslCryptoException, JSONException, MslException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final JSONObject jo = new JSONObject(resp.toJSONString());
            assertEquals(KeyExchangeScheme.JWK_LADDER.name(), jo.getString(KEY_SCHEME));
            final MasterToken masterToken = new MasterToken(pskCtx, jo.getJSONObject(KEY_MASTER_TOKEN));
            assertEquals(PSK_MASTER_TOKEN, masterToken);
            final JSONObject keydata = jo.getJSONObject(KEY_KEYDATA);
            assertArrayEquals(PSK_ENCRYPTION_JWK, Base64.decode(keydata.getString(KEY_ENCRYPTION_KEY)));
            assertArrayEquals(PSK_HMAC_JWK, Base64.decode(keydata.getString(KEY_HMAC_KEY)));
            assertArrayEquals(WRAPDATA, Base64.decode(keydata.getString(KEY_WRAPDATA)));
            assertArrayEquals(WRAP_JWK, Base64.decode(keydata.getString(KEY_WRAP_KEY)));
        }
        
        @Test
        public void create() throws JSONException, MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final JSONObject jo = new JSONObject(resp.toJSONString());
            final KeyResponseData keyResponseData = KeyResponseData.create(pskCtx, jo);
            assertNotNull(keyResponseData);
            assertTrue(keyResponseData instanceof ResponseData);
            
            final ResponseData joResp = (ResponseData)keyResponseData;
            assertArrayEquals(resp.getEncryptionKey(), joResp.getEncryptionKey());
            assertArrayEquals(resp.getHmacKey(), joResp.getHmacKey());
            assertEquals(resp.getKeyExchangeScheme(), joResp.getKeyExchangeScheme());
            assertEquals(resp.getMasterToken(), joResp.getMasterToken());
            assertArrayEquals(resp.getWrapdata(), joResp.getWrapdata());
            assertArrayEquals(resp.getWrapKey(), joResp.getWrapKey());
        }
        
        @Test
        public void missingWrapKey() throws JSONException, MslKeyExchangeException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final JSONObject keydata = resp.getKeydata();
            
            assertNotNull(keydata.remove(KEY_WRAP_KEY));
            
            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void missingWrapdata() throws JSONException, MslKeyExchangeException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final JSONObject keydata = resp.getKeydata();
            
            assertNotNull(keydata.remove(KEY_WRAPDATA));
            
            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void missingEncryptionKey() throws MslKeyExchangeException, MslEncodingException, JSONException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final JSONObject keydata = resp.getKeydata();
            
            assertNotNull(keydata.remove(KEY_ENCRYPTION_KEY));
            
            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void missingHmacKey() throws JSONException, MslKeyExchangeException, MslEncodingException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.JSON_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final JSONObject keydata = resp.getKeydata();
            
            assertNotNull(keydata.remove(KEY_HMAC_KEY));
            
            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void equalsWrapKey() throws MslKeyExchangeException, MslEncodingException, JSONException {
            final byte[] wrapKeyB = Arrays.copyOf(WRAP_JWK, WRAP_JWK.length);
            ++wrapKeyB[0];
            
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, wrapKeyB, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, dataA.getKeydata());
            
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
        public void equalsWrapdata() throws MslKeyExchangeException, MslEncodingException, JSONException {
            final byte[] wrapdataB = Arrays.copyOf(WRAPDATA, WRAPDATA.length);
            ++wrapdataB[0];
            
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, wrapdataB, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, dataA.getKeydata());
            
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
        public void equalsEncryptionKey() throws MslKeyExchangeException, MslEncodingException, JSONException {
            final byte[] encryptionKeyB = Arrays.copyOf(PSK_ENCRYPTION_JWK, PSK_ENCRYPTION_JWK.length);
            ++encryptionKeyB[0];
            
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, encryptionKeyB, PSK_HMAC_JWK);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, dataA.getKeydata());
            
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
        public void equalsHmacKey() throws MslKeyExchangeException, MslEncodingException, JSONException {
            final byte[] hmacKeyB = Arrays.copyOf(PSK_HMAC_JWK, PSK_HMAC_JWK.length);
            ++hmacKeyB[0];
            
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, hmacKeyB);
            final ResponseData dataA2 = new ResponseData(PSK_MASTER_TOKEN, dataA.getKeydata());
            
            assertTrue(dataA.equals(dataA));
            assertEquals(dataA.hashCode(), dataA.hashCode());
            
            assertFalse(dataA.equals(dataB));
            assertFalse(dataB.equals(dataA));
            assertTrue(dataA.hashCode() != dataB.hashCode());
            
            assertTrue(dataA.equals(dataA2));
            assertTrue(dataA2.equals(dataA));
            assertEquals(dataA.hashCode(), dataA2.hashCode());
        }
    }
    
    /** Key exchange factory unit tests. */
        public static class KeyExchangeFactoryTest {
        /**
         * Fake key request data for the JSON Web Key key ladder key exchange
         * scheme.
         */
        private static class FakeKeyRequestData extends KeyRequestData {
            /** Create a new fake key request data. */
            protected FakeKeyRequestData() {
                super(KeyExchangeScheme.JWK_LADDER);
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
         * Fake key response data for the JSON Web Key key ladder key exchange
         * scheme.
         */
        private static class FakeKeyResponseData extends KeyResponseData {
            /** Create a new fake key response data. */
            protected FakeKeyResponseData() {
                super(PSK_MASTER_TOKEN, KeyExchangeScheme.JWK_LADDER);
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
         * Unwrap a JSON Web Key and return the secret key it contains.
         * 
         * @param wrapCryptoContext crypto context for unwrapping the JSON Web Key.
         * @param wrappedJwk the wrapped JSON Web Key.
         * @return the secret key.
         * @throws MslCryptoException if there is an error unwrapping the JSON
         *         Web Key.
         * @throws JSONException if there is an error reconstructing the JSON
         *         Web Key JSON object.
         * @throws MslEncodingException if there is an error parsing the JSON
         *         Web Key JSON object.
         */
        private static SecretKey extractJwkSecretKey(final ICryptoContext wrapCryptoContext, final byte[] wrappedJwk) throws MslCryptoException, JSONException, MslEncodingException {
            final byte[] unwrappedJwk = wrapCryptoContext.unwrap(wrappedJwk);
            final String jwkJson = new String(unwrappedJwk, UTF_8);
            final JsonWebKey jwk = new JsonWebKey(new JSONObject(jwkJson));
            return jwk.getSecretKey();
        }
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @BeforeClass
        public static void setup() {
            random = new Random();
            repository = new MockCryptoContextRepository();
            authutils = new MockAuthenticationUtils();
            factory = new JsonWebKeyLadderExchange(repository, authutils);
            entityAuthData = new PresharedAuthenticationData(PSK_IDENTITY);

            // Not sure why I have to do this again since it's already done by
            // the parent class.
            Security.addProvider(new BouncyCastleProvider());
        }
        
        @AfterClass
        public static void teardown() {
        	entityAuthData = null;
            factory = null;
            authutils = null;
            repository = null;
            random = null;
        }
        
        @Before
        public void reset() {
            authutils.reset();
            pskCtx.getMslStore().clearCryptoContexts();
            pskCtx.getMslStore().clearServiceTokens();
            repository.clear();
        }
        
        /** Random. */
        private static Random random;
        /** JWK key ladder crypto context repository. */
        private static MockCryptoContextRepository repository;
        /** Authentication utilities. */
        private static MockAuthenticationUtils authutils;
        /** Key exchange factory. */
        private static KeyExchangeFactory factory;
        /** Entity authentication data. */
        private static EntityAuthenticationData entityAuthData;
        
        @Test
        public void factory() {
            assertEquals(KeyExchangeScheme.JWK_LADDER, factory.getScheme());
        }
        
        @Test
        public void generateWrapInitialResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException, JSONException {
            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, entityAuthData);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData resp = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.JWK_LADDER, resp.getKeyExchangeScheme());
            final MasterToken masterToken = resp.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(PSK_IDENTITY, masterToken.getIdentity());
            
            // Unwrap the new wrapping key and create a crypto context from it.
            assertTrue(resp instanceof ResponseData);
            final ResponseData respdata = (ResponseData)resp;
            final SecretKey wrappingKey = extractJwkSecretKey(WRAP_CRYPTO_CONTEXT, respdata.getWrapKey());
            final JwkCryptoContext wrapCryptoContext = new AesKwJwkCryptoContext(wrappingKey);
            
            // Unwrap the session keys.
            final SecretKey encryptionKey = extractJwkSecretKey(wrapCryptoContext, respdata.getEncryptionKey());
            assertArrayEquals(masterToken.getEncryptionKey().getEncoded(), encryptionKey.getEncoded());
            final SecretKey hmacKey = extractJwkSecretKey(wrapCryptoContext, respdata.getHmacKey());
            assertArrayEquals(masterToken.getSignatureKey().getEncoded(), hmacKey.getEncoded());
        }
        
        @Test
        public void generatePskInitialResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException, JSONException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, entityAuthData);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData resp = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.JWK_LADDER, resp.getKeyExchangeScheme());
            final MasterToken masterToken = resp.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(PSK_IDENTITY, masterToken.getIdentity());
            
            // Unwrap the new wrapping key and create a crypto context from it.
            assertTrue(resp instanceof ResponseData);
            final ResponseData respdata = (ResponseData)resp;
            final SecretKey wrappingKey = extractJwkSecretKey(PSK_CRYPTO_CONTEXT, respdata.getWrapKey());
            final JwkCryptoContext wrapCryptoContext = new AesKwJwkCryptoContext(wrappingKey);
            
            // Unwrap the session keys.
            final SecretKey encryptionKey = extractJwkSecretKey(wrapCryptoContext, respdata.getEncryptionKey());
            assertArrayEquals(masterToken.getEncryptionKey().getEncoded(), encryptionKey.getEncoded());
            final SecretKey hmacKey = extractJwkSecretKey(wrapCryptoContext, respdata.getHmacKey());
            assertArrayEquals(masterToken.getSignatureKey().getEncoded(), hmacKey.getEncoded());
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestInitialResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            final KeyRequestData req = new FakeKeyRequestData();
            factory.generateResponse(pskCtx, req, entityAuthData);
        }
        
        @Test
        public void generateWrapSubsequentResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException, MslException, JSONException {
            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, PSK_MASTER_TOKEN);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData resp = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.JWK_LADDER, resp.getKeyExchangeScheme());
            final MasterToken masterToken = resp.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(PSK_MASTER_TOKEN.getIdentity(), masterToken.getIdentity());
            assertEquals(PSK_MASTER_TOKEN.getSerialNumber(), masterToken.getSerialNumber());
            assertEquals(PSK_MASTER_TOKEN.getSequenceNumber() + 1, masterToken.getSequenceNumber());
            
            // Unwrap the new wrapping key and create a crypto context from it.
            assertTrue(resp instanceof ResponseData);
            final ResponseData respdata = (ResponseData)resp;
            final SecretKey wrappingKey = extractJwkSecretKey(WRAP_CRYPTO_CONTEXT, respdata.getWrapKey());
            final JwkCryptoContext wrapCryptoContext = new AesKwJwkCryptoContext(wrappingKey);
            
            // Unwrap the session keys.
            final SecretKey encryptionKey = extractJwkSecretKey(wrapCryptoContext, respdata.getEncryptionKey());
            assertArrayEquals(masterToken.getEncryptionKey().getEncoded(), encryptionKey.getEncoded());
            final SecretKey hmacKey = extractJwkSecretKey(wrapCryptoContext, respdata.getHmacKey());
            assertArrayEquals(masterToken.getSignatureKey().getEncoded(), hmacKey.getEncoded());
        }
        
        @Test
        public void generatePskSubsequentResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException, MslException, JSONException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, PSK_MASTER_TOKEN);
            assertNotNull(keyxData);
            assertNotNull(keyxData.cryptoContext);
            assertNotNull(keyxData.keyResponseData);
            
            final KeyResponseData resp = keyxData.keyResponseData;
            assertEquals(KeyExchangeScheme.JWK_LADDER, resp.getKeyExchangeScheme());
            final MasterToken masterToken = resp.getMasterToken();
            assertNotNull(masterToken);
            assertEquals(PSK_MASTER_TOKEN.getIdentity(), masterToken.getIdentity());
            assertEquals(PSK_MASTER_TOKEN.getSerialNumber(), masterToken.getSerialNumber());
            assertEquals(PSK_MASTER_TOKEN.getSequenceNumber() + 1, masterToken.getSequenceNumber());
            
            // Unwrap the new wrapping key and create a crypto context from it.
            assertTrue(resp instanceof ResponseData);
            final ResponseData respdata = (ResponseData)resp;
            final SecretKey wrappingKey = extractJwkSecretKey(PSK_CRYPTO_CONTEXT, respdata.getWrapKey());
            final JwkCryptoContext wrapCryptoContext = new AesKwJwkCryptoContext(wrappingKey);
            
            // Unwrap the session keys.
            final SecretKey encryptionKey = extractJwkSecretKey(wrapCryptoContext, respdata.getEncryptionKey());
            assertArrayEquals(masterToken.getEncryptionKey().getEncoded(), encryptionKey.getEncoded());
            final SecretKey hmacKey = extractJwkSecretKey(wrapCryptoContext, respdata.getHmacKey());
            assertArrayEquals(masterToken.getSignatureKey().getEncoded(), hmacKey.getEncoded());
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestSubsequentResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException, MslException {
            final KeyRequestData req = new FakeKeyRequestData();
            factory.generateResponse(pskCtx, req, PSK_MASTER_TOKEN);
        }
        
        @Test(expected = MslMasterTokenException.class)
        public void untrustedMasterTokenSubsequentResponse() throws MslEncodingException, MslCryptoException, JSONException, MslException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final MasterToken masterToken = MslTestUtils.getUntrustedMasterToken(pskCtx);
            factory.generateResponse(pskCtx, req, masterToken);
        }
        
        @Test
        public void getWrapCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, entityAuthData);
            final ICryptoContext reqCryptoContext = keyxData.cryptoContext;
            final KeyResponseData resp = keyxData.keyResponseData;

            // We must put the wrapping key into the repository to create the
            // response crypto context.
            repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
            assertNotNull(repository.getCryptoContext(WRAPDATA));
            
            final ICryptoContext respCryptoContext = factory.getCryptoContext(pskCtx, req, resp, null);
            
            final byte[] wrapdata = repository.getWrapdata();
            assertNotNull(wrapdata);
            assertArrayEquals(((ResponseData)resp).getWrapdata(), wrapdata);
            
            assertNull(repository.getCryptoContext(WRAPDATA));
            
            final byte[] data = new byte[32];
            random.nextBytes(data);
            
            // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            final byte[] requestCiphertext = reqCryptoContext.encrypt(data);
            final byte[] responseCiphertext = respCryptoContext.encrypt(data);
            assertFalse(Arrays.equals(data, requestCiphertext));
            assertFalse(Arrays.equals(data, responseCiphertext));
            
            // Signatures should always be equal.
            final byte[] requestSignature = reqCryptoContext.sign(data);
            final byte[] responseSignature = respCryptoContext.sign(data);
            assertFalse(Arrays.equals(data, requestSignature));
            assertFalse(Arrays.equals(data, responseSignature));
            assertArrayEquals(requestSignature, responseSignature);
            
            // Plaintext should always be equal to the original message.
            final byte[] requestPlaintext = reqCryptoContext.decrypt(responseCiphertext);
            final byte[] responsePlaintext = respCryptoContext.decrypt(requestCiphertext);
            assertNotNull(requestPlaintext);
            assertArrayEquals(data, requestPlaintext);
            assertArrayEquals(requestPlaintext, responsePlaintext);
            
            // Verification should always succeed.
            assertTrue(reqCryptoContext.verify(data, responseSignature));
            assertTrue(respCryptoContext.verify(data, requestSignature));
        }
        
        @Test
        public void getPskCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, entityAuthData);
            final ICryptoContext reqCryptoContext = keyxData.cryptoContext;
            final KeyResponseData resp = keyxData.keyResponseData;
            
            assertNull(repository.getWrapdata());
            
            final ICryptoContext respCryptoContext = factory.getCryptoContext(pskCtx, req, resp, null);
            
            final byte[] wrapdata = repository.getWrapdata();
            assertNotNull(wrapdata);
            assertArrayEquals(((ResponseData)resp).getWrapdata(), wrapdata);
            
            final byte[] data = new byte[32];
            random.nextBytes(data);
            
            // Ciphertext won't always be equal depending on how it was
            // enveloped. So we cannot check for equality or inequality.
            final byte[] requestCiphertext = reqCryptoContext.encrypt(data);
            final byte[] responseCiphertext = respCryptoContext.encrypt(data);
            assertFalse(Arrays.equals(data, requestCiphertext));
            assertFalse(Arrays.equals(data, responseCiphertext));
            
            // Signatures should always be equal.
            final byte[] requestSignature = reqCryptoContext.sign(data);
            final byte[] responseSignature = respCryptoContext.sign(data);
            assertFalse(Arrays.equals(data, requestSignature));
            assertFalse(Arrays.equals(data, responseSignature));
            assertArrayEquals(requestSignature, responseSignature);
            
            // Plaintext should always be equal to the original message.
            final byte[] requestPlaintext = reqCryptoContext.decrypt(responseCiphertext);
            final byte[] responsePlaintext = respCryptoContext.decrypt(requestCiphertext);
            assertNotNull(requestPlaintext);
            assertArrayEquals(data, requestPlaintext);
            assertArrayEquals(requestPlaintext, responsePlaintext);
            
            // Verification should always succeed.
            assertTrue(reqCryptoContext.verify(data, responseSignature));
            assertTrue(respCryptoContext.verify(data, requestSignature));
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, entityAuthData);
            final KeyResponseData resp = keyxData.keyResponseData;
            
            final KeyRequestData fakeReq = new FakeKeyRequestData();
            factory.getCryptoContext(pskCtx, fakeReq, resp, null);
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongResponseCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyResponseData fakeResp = new FakeKeyResponseData();
            factory.getCryptoContext(pskCtx, req, fakeResp, null);
        }
        
        @Test
        public void pskUnsupportedCryptoContext() throws MslKeyExchangeException, MslEntityAuthException, MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNSUPPORTED_KEYX_MECHANISM);

            final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
            
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(ctx, req, entityAuthData);
            final KeyResponseData resp = keyxData.keyResponseData;
            
            ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
            factory.getCryptoContext(ctx, req, resp, null);
        }
        
        @Test
        public void wrapKeyMissingCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_WRAPPING_KEY_MISSING);

            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, entityAuthData);
            final KeyResponseData resp = keyxData.keyResponseData;
            
            factory.getCryptoContext(pskCtx, req, resp, null);
        }
        
        @Test
        public void invalidWrapJwkCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.INVALID_JWK);

            final byte[] data = new byte[16];
            random.nextBytes(data);
            final byte[] wrapJwk = WRAP_CRYPTO_CONTEXT.wrap(data);
            
            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyResponseData invalidResp = new ResponseData(PSK_MASTER_TOKEN, wrapJwk, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            
            repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
            factory.getCryptoContext(pskCtx, req, invalidResp, null);
        }
        
        @Test
        public void invalidEncryptionJwkCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.INVALID_JWK);

            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, entityAuthData);
            final ResponseData resp = (ResponseData)keyxData.keyResponseData;
            
            // First get the new crypto context. This installs the returned
            // wrapping key in the repository.
            repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
            assertArrayEquals(WRAPDATA, repository.getWrapdata());
            factory.getCryptoContext(pskCtx, req, resp, null);
            assertFalse(Arrays.equals(WRAPDATA, repository.getWrapdata()));
            
            // Now make the invalid response.
            final byte[] data = new byte[16];
            random.nextBytes(data);
            final ICryptoContext wrapCryptoContext = repository.getCryptoContext(repository.getWrapdata());
            final byte[] encryptionJwk = wrapCryptoContext.wrap(data);
            
            // Extract values from the response.
            final MasterToken masterToken = resp.getMasterToken();
            final byte[] wrapJwk = resp.getWrapKey();
            final byte[] wrapdata = resp.getWrapdata();
            final byte[] hmacJwk = resp.getHmacKey();
            
            final KeyResponseData invalidResp = new ResponseData(masterToken, wrapJwk, wrapdata, encryptionJwk, hmacJwk);
            
            // Reinstall the previous wrap crypto context.
            repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
            assertArrayEquals(WRAPDATA, repository.getWrapdata());
            factory.getCryptoContext(pskCtx, req, invalidResp, null);
        }
        
        @Test
        public void invalidHmacJwkCryptoContext() throws MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.INVALID_JWK);

            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, req, entityAuthData);
            final ResponseData resp = (ResponseData)keyxData.keyResponseData;
            
            // First get the new crypto context. This installs the returned
            // wrapping key in the repository.
            repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
            assertArrayEquals(WRAPDATA, repository.getWrapdata());
            factory.getCryptoContext(pskCtx, req, resp, null);
            assertFalse(Arrays.equals(WRAPDATA, repository.getWrapdata()));
            
            // Now make the invalid response.
            final byte[] data = new byte[16];
            random.nextBytes(data);
            final ICryptoContext wrapCryptoContext = repository.getCryptoContext(repository.getWrapdata());
            final byte[] hmacJwk = wrapCryptoContext.wrap(data);
            
            // Extract values from the response.
            final MasterToken masterToken = resp.getMasterToken();
            final byte[] wrapJwk = resp.getWrapKey();
            final byte[] wrapdata = resp.getWrapdata();
            final byte[] encryptionJwk = resp.getEncryptionKey();
            
            final KeyResponseData invalidResp = new ResponseData(masterToken, wrapJwk, wrapdata, encryptionJwk, hmacJwk);
            
            // Reinstall the previous wrap crypto context.
            repository.addCryptoContext(WRAPDATA, WRAP_CRYPTO_CONTEXT);
            assertArrayEquals(WRAPDATA, repository.getWrapdata());
            factory.getCryptoContext(pskCtx, req, invalidResp, null);
        }
    }
}
