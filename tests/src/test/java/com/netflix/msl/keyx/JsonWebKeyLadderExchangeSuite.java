/**
 * Copyright (c) 2013-2017 Netflix, Inc.  All rights reserved.
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

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.AesKwJwkCryptoContext;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.JwkCryptoContext;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.Mechanism;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.RequestData;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange.ResponseData;
import com.netflix.msl.keyx.KeyExchangeFactory.KeyExchangeData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.AuthenticationUtils;
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
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key key exchange scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key key request data. */
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
            encoder = pskCtx.getMslEncoderFactory();
            
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
            WRAP_JWK = PSK_CRYPTO_CONTEXT.wrap(wrapJwk.toMslEncoding(encoder, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
            
            // The wrap data is an AES-128 key wrapped by the primary MSL
            // context. Technically we shouldn't know this but that's the only
            // way to verify things.
            WRAPDATA = pskCtx.getMslCryptoContext().wrap(wrappingKey, encoder, ENCODER_FORMAT);

            final WrapCryptoContextRepository repository = new MockCryptoContextRepository();
            final AuthenticationUtils authutils = new MockAuthenticationUtils();
            final KeyExchangeFactory keyxFactory = new JsonWebKeyLadderExchange(repository, authutils);
            pskCtx.addKeyExchangeFactory(keyxFactory);
    
            PSK_MASTER_TOKEN = MslTestUtils.getMasterToken(pskCtx, 1, 1);
            final SecretKey pskEncryptionKey = PSK_MASTER_TOKEN.getEncryptionKey();
            final JsonWebKey pskEncryptionJwk = new JsonWebKey(Usage.enc, Algorithm.A128CBC, false, null, pskEncryptionKey);
            PSK_ENCRYPTION_JWK = WRAP_CRYPTO_CONTEXT.wrap(pskEncryptionJwk.toMslEncoding(encoder, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
            final SecretKey pskHmacKey = PSK_MASTER_TOKEN.getSignatureKey();
            final JsonWebKey pskHmacJwk = new JsonWebKey(Usage.sig, Algorithm.HS256, false, null, pskHmacKey);
            PSK_HMAC_JWK = WRAP_CRYPTO_CONTEXT.wrap(pskHmacJwk.toMslEncoding(encoder, ENCODER_FORMAT), encoder, ENCODER_FORMAT);
        }
    }
    
    @AfterClass
    public static synchronized void teardown() {
        // Teardown causes problems because the data is shared by the inner
        // classes, so don't do any cleanup.
    }
    
    /** PSK MSL context. */
    private static MockMslContext pskCtx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;

    /** Request data unit tests. */
    public static class RequestDataTest {
        /** Key wrap key wrapping mechanism. */
        private static final String KEY_MECHANISM = "mechanism";
        /** Key public key. */
        private static final String KEY_PUBLIC_KEY = "publickey";
        /** Key wrap data. */
        private static final String KEY_WRAPDATA = "wrapdata";
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctorsWrap() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            assertEquals(KeyExchangeScheme.JWK_LADDER, req.getKeyExchangeScheme());
            assertEquals(Mechanism.WRAP, req.getMechanism());
            assertArrayEquals(WRAPDATA, req.getWrapdata());
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);
            
            final RequestData moReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
            assertEquals(req.getMechanism(), moReq.getMechanism());
            assertArrayEquals(req.getWrapdata(), moReq.getWrapdata());
            final MslObject moKeydata = req.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }
        
        @Test
        public void jsonWrap() throws MslException, MslEncoderException {
            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final MslObject mo = MslTestUtils.toMslObject(encoder, req);
            assertEquals(KeyExchangeScheme.JWK_LADDER.name(), mo.getString(KEY_SCHEME));
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            assertEquals(Mechanism.WRAP.name(), keydata.getString(KEY_MECHANISM));
            assertFalse(keydata.has(KEY_PUBLIC_KEY));
            assertArrayEquals(WRAPDATA, keydata.getBytes(KEY_WRAPDATA));
        }
        
        @Test
        public void createWrap() throws MslException, MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslCryptoException, MslEncoderException {
            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final MslObject mo = MslTestUtils.toMslObject(encoder, req);
            final KeyRequestData keyRequestData = KeyRequestData.create(pskCtx, mo);
            assertNotNull(keyRequestData);
            assertTrue(keyRequestData instanceof RequestData);
            
            final RequestData moReq = (RequestData)keyRequestData;
            assertEquals(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
            assertEquals(req.getMechanism(), moReq.getMechanism());
            assertArrayEquals(req.getWrapdata(), moReq.getWrapdata());
        }
        
        @Test(expected = MslInternalException.class)
        public void ctorWrapNullWrapdata() {
            new RequestData(Mechanism.WRAP, null);
        }
        
        @Test
        public void ctorsPsk() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            final RequestData req = new RequestData(Mechanism.PSK, null);
            assertEquals(KeyExchangeScheme.JWK_LADDER, req.getKeyExchangeScheme());
            assertEquals(Mechanism.PSK, req.getMechanism());
            assertNull(req.getWrapdata());
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);
            
            final RequestData moReq = new RequestData(keydata);
            assertEquals(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
            assertEquals(req.getMechanism(), moReq.getMechanism());
            assertNull(moReq.getWrapdata());
            final MslObject moKeydata = req.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }
        
        @Test
        public void jsonPsk() throws MslException, MslEncoderException {
            final RequestData req = new RequestData(Mechanism.PSK, null);
            final MslObject mo = MslTestUtils.toMslObject(encoder, req);
            assertEquals(KeyExchangeScheme.JWK_LADDER.name(), mo.getString(KEY_SCHEME));
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            assertEquals(Mechanism.PSK.name(), keydata.getString(KEY_MECHANISM));
            assertFalse(keydata.has(KEY_PUBLIC_KEY));
            assertFalse(keydata.has(KEY_WRAPDATA));
        }
        
        @Test
        public void createPsk() throws MslEncodingException, MslEntityAuthException, MslKeyExchangeException, MslException, MslCryptoException, MslEncoderException {
            final RequestData req = new RequestData(Mechanism.PSK, null);
            final MslObject mo = MslTestUtils.toMslObject(encoder, req);
            final KeyRequestData keyRequestData = KeyRequestData.create(pskCtx, mo);
            assertNotNull(keyRequestData);
            assertTrue(keyRequestData instanceof RequestData);
            
            final RequestData moReq = (RequestData)keyRequestData;
            assertEquals(req.getKeyExchangeScheme(), moReq.getKeyExchangeScheme());
            assertEquals(req.getMechanism(), moReq.getMechanism());
            assertNull(moReq.getWrapdata());
        }
        
        @Test
        public void missingMechanism() throws MslException, MslCryptoException, MslKeyExchangeException, MslEncodingException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final RequestData req = new RequestData(Mechanism.PSK, null);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_MECHANISM));
            
            new RequestData(keydata);
        }
        
        @Test
        public void invalidMechanism() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.UNIDENTIFIED_KEYX_MECHANISM);

            final RequestData req = new RequestData(Mechanism.PSK, null);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            
            keydata.put(KEY_MECHANISM, "x");
            
            new RequestData(keydata);
        }
        
        @Test
        public void wrapMissingWrapdata() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_WRAPDATA));
            
            new RequestData(keydata);
        }
        
        @Test
        public void wrapInvalidWrapdata() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_WRAPPING_KEY_MISSING);

            final RequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final MslObject keydata = req.getKeydata(encoder, ENCODER_FORMAT);
            
            keydata.put(KEY_WRAPDATA, new byte[0]);
            
            new RequestData(keydata);
        }
        
        @Test
        public void equalsMechanism() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            final RequestData dataA = new RequestData(Mechanism.WRAP, WRAPDATA);
            final RequestData dataB = new RequestData(Mechanism.PSK, null);
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
        public void equalsWrapdata() throws MslCryptoException, MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            final byte[] wrapdataB = Arrays.copyOf(WRAPDATA, WRAPDATA.length);
            ++wrapdataB[0];
            
            final RequestData dataA = new RequestData(Mechanism.WRAP, WRAPDATA);
            final RequestData dataB = new RequestData(Mechanism.WRAP, wrapdataB);
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
    }
    
    /** Response data unit tests. */
        public static class ResponseDataTest {
        /** Key master token. */
        private static final String KEY_MASTER_TOKEN = "mastertoken";
        
        /** Key wrapping key. */
        private static final String KEY_WRAP_KEY = "wrapkey";
        /** Key wrapping key data. */
        private static final String KEY_WRAPDATA = "wrapdata";
        /** Key encrypted encryption key. */
        private static final String KEY_ENCRYPTION_KEY = "encryptionkey";
        /** Key encrypted HMAC key. */
        private static final String KEY_HMAC_KEY = "hmackey";
        
        @Rule
        public ExpectedMslException thrown = ExpectedMslException.none();
        
        @Test
        public void ctors() throws MslException, MslKeyExchangeException, MslEncodingException, MslEncoderException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            assertArrayEquals(PSK_ENCRYPTION_JWK, resp.getEncryptionKey());
            assertArrayEquals(PSK_HMAC_JWK, resp.getHmacKey());
            assertEquals(KeyExchangeScheme.JWK_LADDER, resp.getKeyExchangeScheme());
            assertEquals(PSK_MASTER_TOKEN, resp.getMasterToken());
            assertArrayEquals(WRAPDATA, resp.getWrapdata());
            assertArrayEquals(WRAP_JWK, resp.getWrapKey());
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(keydata);
            
            final ResponseData moResp = new ResponseData(PSK_MASTER_TOKEN, keydata);
            assertArrayEquals(resp.getEncryptionKey(), moResp.getEncryptionKey());
            assertArrayEquals(resp.getHmacKey(), moResp.getHmacKey());
            assertEquals(resp.getKeyExchangeScheme(), moResp.getKeyExchangeScheme());
            assertEquals(resp.getMasterToken(), moResp.getMasterToken());
            assertArrayEquals(resp.getWrapdata(), moResp.getWrapdata());
            assertArrayEquals(resp.getWrapKey(), moResp.getWrapKey());
            final MslObject moKeydata = moResp.getKeydata(encoder, ENCODER_FORMAT);
            assertNotNull(moKeydata);
            assertTrue(MslEncoderUtils.equalObjects(keydata, moKeydata));
        }
        
        @Test
        public void json() throws MslEncodingException, MslCryptoException, MslException, MslException, MslEncoderException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final MslObject mo = MslTestUtils.toMslObject(encoder, resp);
            assertEquals(KeyExchangeScheme.JWK_LADDER.name(), mo.getString(KEY_SCHEME));
            final MasterToken masterToken = new MasterToken(pskCtx, mo.getMslObject(KEY_MASTER_TOKEN, encoder));
            assertEquals(PSK_MASTER_TOKEN, masterToken);
            final MslObject keydata = mo.getMslObject(KEY_KEYDATA, encoder);
            assertArrayEquals(PSK_ENCRYPTION_JWK, keydata.getBytes(KEY_ENCRYPTION_KEY));
            assertArrayEquals(PSK_HMAC_JWK, keydata.getBytes(KEY_HMAC_KEY));
            assertArrayEquals(WRAPDATA, keydata.getBytes(KEY_WRAPDATA));
            assertArrayEquals(WRAP_JWK, keydata.getBytes(KEY_WRAP_KEY));
        }
        
        @Test
        public void create() throws MslException, MslEncodingException, MslCryptoException, MslKeyExchangeException, MslException, MslEncoderException {
            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final MslObject mo = MslTestUtils.toMslObject(encoder, resp);
            final KeyResponseData keyResponseData = KeyResponseData.create(pskCtx, mo);
            assertNotNull(keyResponseData);
            assertTrue(keyResponseData instanceof ResponseData);
            
            final ResponseData moResp = (ResponseData)keyResponseData;
            assertArrayEquals(resp.getEncryptionKey(), moResp.getEncryptionKey());
            assertArrayEquals(resp.getHmacKey(), moResp.getHmacKey());
            assertEquals(resp.getKeyExchangeScheme(), moResp.getKeyExchangeScheme());
            assertEquals(resp.getMasterToken(), moResp.getMasterToken());
            assertArrayEquals(resp.getWrapdata(), moResp.getWrapdata());
            assertArrayEquals(resp.getWrapKey(), moResp.getWrapKey());
        }
        
        @Test
        public void missingWrapKey() throws MslException, MslKeyExchangeException, MslEncodingException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_WRAP_KEY));
            
            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void missingWrapdata() throws MslException, MslKeyExchangeException, MslEncodingException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_WRAPDATA));
            
            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void missingEncryptionKey() throws MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_ENCRYPTION_KEY));
            
            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void missingHmacKey() throws MslException, MslKeyExchangeException, MslEncodingException, MslEncoderException {
            thrown.expect(MslEncodingException.class);
            thrown.expectMslError(MslError.MSL_PARSE_ERROR);

            final ResponseData resp = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final MslObject keydata = resp.getKeydata(encoder, ENCODER_FORMAT);
            
            assertNotNull(keydata.remove(KEY_HMAC_KEY));
            
            new ResponseData(PSK_MASTER_TOKEN, keydata);
        }
        
        @Test
        public void equalsWrapKey() throws MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            final byte[] wrapKeyB = Arrays.copyOf(WRAP_JWK, WRAP_JWK.length);
            ++wrapKeyB[0];
            
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, wrapKeyB, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
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
        public void equalsWrapdata() throws MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            final byte[] wrapdataB = Arrays.copyOf(WRAPDATA, WRAPDATA.length);
            ++wrapdataB[0];
            
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, wrapdataB, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
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
        public void equalsEncryptionKey() throws MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            final byte[] encryptionKeyB = Arrays.copyOf(PSK_ENCRYPTION_JWK, PSK_ENCRYPTION_JWK.length);
            ++encryptionKeyB[0];
            
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, encryptionKeyB, PSK_HMAC_JWK);
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
        public void equalsHmacKey() throws MslKeyExchangeException, MslEncodingException, MslException, MslEncoderException {
            final byte[] hmacKeyB = Arrays.copyOf(PSK_HMAC_JWK, PSK_HMAC_JWK.length);
            ++hmacKeyB[0];
            
            final ResponseData dataA = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, PSK_HMAC_JWK);
            final ResponseData dataB = new ResponseData(PSK_MASTER_TOKEN, WRAP_JWK, WRAPDATA, PSK_ENCRYPTION_JWK, hmacKeyB);
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
             * @see com.netflix.msl.keyx.KeyRequestData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
             */
            @Override
            protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
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
             * @see com.netflix.msl.keyx.KeyResponseData#getKeydata(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
             */
            @Override
            protected MslObject getKeydata(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
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
         * @throws MslException if there is an error reconstructing the JSON
         *         Web Key MSL object.
         * @throws MslEncodingException if there is an error parsing the JSON
         *         Web Key MSL object.
         * @throws MslEncoderException if there is an error parsing the data.
         */
        private static SecretKey extractJwkSecretKey(final ICryptoContext wrapCryptoContext, final byte[] wrappedJwk) throws MslCryptoException, MslException, MslEncodingException, MslEncoderException {
            final byte[] unwrappedJwk = wrapCryptoContext.unwrap(wrappedJwk, encoder);
            final JsonWebKey jwk = new JsonWebKey(encoder.parseObject(unwrappedJwk));
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
        public void generateWrapInitialResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException, MslException, MslEncoderException {
            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
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
        public void generatePskInitialResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException, MslException, MslEncoderException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
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
            factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
        }
        
        @Test
        public void generateWrapSubsequentResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException, MslException, MslException, MslEncoderException {
            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, PSK_MASTER_TOKEN);
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
        public void generatePskSubsequentResponse() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslMasterTokenException, MslEntityAuthException, MslException, MslException, MslEncoderException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, PSK_MASTER_TOKEN);
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
            factory.generateResponse(pskCtx, ENCODER_FORMAT, req, PSK_MASTER_TOKEN);
        }
        
        @Test(expected = MslMasterTokenException.class)
        public void untrustedMasterTokenSubsequentResponse() throws MslEncodingException, MslCryptoException, MslException, MslException, MslEncoderException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final MasterToken masterToken = MslTestUtils.getUntrustedMasterToken(pskCtx);
            factory.generateResponse(pskCtx, ENCODER_FORMAT, req, masterToken);
        }
        
        @Test
        public void getWrapCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
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
            final byte[] requestCiphertext = reqCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
            final byte[] responseCiphertext = respCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
            assertFalse(Arrays.equals(data, requestCiphertext));
            assertFalse(Arrays.equals(data, responseCiphertext));
            
            // Signatures should always be equal.
            final byte[] requestSignature = reqCryptoContext.sign(data, encoder, ENCODER_FORMAT);
            final byte[] responseSignature = respCryptoContext.sign(data, encoder, ENCODER_FORMAT);
            assertFalse(Arrays.equals(data, requestSignature));
            assertFalse(Arrays.equals(data, responseSignature));
            assertArrayEquals(requestSignature, responseSignature);
            
            // Plaintext should always be equal to the original message.
            final byte[] requestPlaintext = reqCryptoContext.decrypt(responseCiphertext, encoder);
            final byte[] responsePlaintext = respCryptoContext.decrypt(requestCiphertext, encoder);
            assertNotNull(requestPlaintext);
            assertArrayEquals(data, requestPlaintext);
            assertArrayEquals(requestPlaintext, responsePlaintext);
            
            // Verification should always succeed.
            assertTrue(reqCryptoContext.verify(data, responseSignature, encoder));
            assertTrue(respCryptoContext.verify(data, requestSignature, encoder));
        }
        
        @Test
        public void getPskCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
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
            final byte[] requestCiphertext = reqCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
            final byte[] responseCiphertext = respCryptoContext.encrypt(data, encoder, ENCODER_FORMAT);
            assertFalse(Arrays.equals(data, requestCiphertext));
            assertFalse(Arrays.equals(data, responseCiphertext));
            
            // Signatures should always be equal.
            final byte[] requestSignature = reqCryptoContext.sign(data, encoder, ENCODER_FORMAT);
            final byte[] responseSignature = respCryptoContext.sign(data, encoder, ENCODER_FORMAT);
            assertFalse(Arrays.equals(data, requestSignature));
            assertFalse(Arrays.equals(data, responseSignature));
            assertArrayEquals(requestSignature, responseSignature);
            
            // Plaintext should always be equal to the original message.
            final byte[] requestPlaintext = reqCryptoContext.decrypt(responseCiphertext, encoder);
            final byte[] responsePlaintext = respCryptoContext.decrypt(requestCiphertext, encoder);
            assertNotNull(requestPlaintext);
            assertArrayEquals(data, requestPlaintext);
            assertArrayEquals(requestPlaintext, responsePlaintext);
            
            // Verification should always succeed.
            assertTrue(reqCryptoContext.verify(data, responseSignature, encoder));
            assertTrue(respCryptoContext.verify(data, requestSignature, encoder));
        }
        
        @Test(expected = MslInternalException.class)
        public void wrongRequestCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            final KeyRequestData req = new RequestData(Mechanism.PSK, null);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
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
            final KeyExchangeData keyxData = factory.generateResponse(ctx, ENCODER_FORMAT, req, entityAuthData);
            final KeyResponseData resp = keyxData.keyResponseData;
            
            ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.PSK);
            factory.getCryptoContext(ctx, req, resp, null);
        }
        
        @Test
        public void wrapKeyMissingCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.KEYX_WRAPPING_KEY_MISSING);

            final KeyRequestData req = new RequestData(Mechanism.WRAP, WRAPDATA);
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
            final KeyResponseData resp = keyxData.keyResponseData;
            
            factory.getCryptoContext(pskCtx, req, resp, null);
        }
        
        @Test
        public void invalidWrapJwkCryptoContext() throws MslKeyExchangeException, MslCryptoException, MslEncodingException, MslEntityAuthException, MslException {
            thrown.expect(MslKeyExchangeException.class);
            thrown.expectMslError(MslError.INVALID_JWK);

            final byte[] data = new byte[16];
            random.nextBytes(data);
            final byte[] wrapJwk = WRAP_CRYPTO_CONTEXT.wrap(data, encoder, ENCODER_FORMAT);
            
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
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
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
            final byte[] encryptionJwk = wrapCryptoContext.wrap(data, encoder, ENCODER_FORMAT);
            
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
            final KeyExchangeData keyxData = factory.generateResponse(pskCtx, ENCODER_FORMAT, req, entityAuthData);
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
            final byte[] hmacJwk = wrapCryptoContext.wrap(data, encoder, ENCODER_FORMAT);
            
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
