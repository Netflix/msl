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
package com.netflix.msl.entityauth;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslEntityAuthException;
import com.netflix.msl.MslError;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;

/**
 * RSA asymmetric keys entity authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class RsaAuthenticationFactoryTest {
    /** JSON key entity identity. */
    private static final String KEY_IDENTITY = "identity";

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();

    /** Authentication utilities. */
    private static MockAuthenticationUtils authutils;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.RSA, false);
        final MockRsaStore rsaStore = new MockRsaStore();
        rsaStore.addPublicKey(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, MockRsaAuthenticationFactory.RSA_PUBKEY);
        authutils = new MockAuthenticationUtils();
        factory = new RsaAuthenticationFactory(rsaStore, authutils);
        ctx.addEntityAuthenticationFactory(factory);
    }
    
    @AfterClass
    public static void teardown() {
        factory = null;
        authutils = null;
        ctx = null;
    }
    
    @After
    public void reset() {
        authutils.reset();
    }
    
    @Test
    public void createData() throws MslEncodingException, MslEntityAuthException, JSONException, MslCryptoException {
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final JSONObject entityAuthJO = data.getAuthData();
        
        final EntityAuthenticationData authdata = factory.createData(ctx, entityAuthJO);
        assertNotNull(authdata);
        assertTrue(authdata instanceof RsaAuthenticationData);
        
        final JSONObject dataJo = new JSONObject(data.toJSONString());
        final JSONObject authdataJo = new JSONObject(authdata.toJSONString());
        assertTrue(JsonUtils.equals(dataJo, authdataJo));
    }
    
    @Test
    public void encodeException() throws MslEncodingException, MslEntityAuthException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final JSONObject entityAuthJO = data.getAuthData();
        entityAuthJO.remove(KEY_IDENTITY);
        factory.createData(ctx, entityAuthJO);
    }
    
    @Test
    public void cryptoContext() throws MslEntityAuthException, MslCryptoException {
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, data);
        assertNotNull(cryptoContext);
    }

    @Test
    public void unknownKeyId() throws MslEntityAuthException, MslCryptoException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.RSA_PUBLICKEY_NOT_FOUND);

        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, "x");
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void localCryptoContext() throws MslCryptoException, MslEntityAuthException {
        final MockRsaStore rsaStore = new MockRsaStore();
        rsaStore.addPrivateKey(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, MockRsaAuthenticationFactory.RSA_PRIVKEY);
        final EntityAuthenticationFactory factory = new RsaAuthenticationFactory(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, rsaStore, authutils);
        
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, data);
        
        final byte[] plaintext = new byte[16];
        ctx.getRandom().nextBytes(plaintext);
        cryptoContext.sign(plaintext);
    }
    
    @Test
    public void missingPrivateKey() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.RSA_PRIVATEKEY_NOT_FOUND);
        
        final MockRsaStore rsaStore = new MockRsaStore();
        rsaStore.addPublicKey(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, MockRsaAuthenticationFactory.RSA_PUBKEY);
        final EntityAuthenticationFactory factory = new RsaAuthenticationFactory(MockRsaAuthenticationFactory.RSA_PUBKEY_ID, rsaStore, authutils);
        
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, MockRsaAuthenticationFactory.RSA_PUBKEY_ID);
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void revoked() throws MslEntityAuthException, MslCryptoException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITY_REVOKED);

        authutils.revokeEntity(MockRsaAuthenticationFactory.RSA_ESN);
        final RsaAuthenticationData data = new RsaAuthenticationData(MockRsaAuthenticationFactory.RSA_ESN, "x");
        factory.getCryptoContext(ctx, data);
    }
    
    /** MSL context. */
    private static MockMslContext ctx;
    /** Entity authentication factory. */
    private static EntityAuthenticationFactory factory;
}
