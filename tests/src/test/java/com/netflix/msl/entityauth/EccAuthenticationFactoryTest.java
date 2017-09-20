/**
 * Copyright (c) 2016-2017 Netflix, Inc.  All rights reserved.
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
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * ECC asymmetric keys entity authentication factory unit tests.
 * 
 */
public class EccAuthenticationFactoryTest {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;
    
    /** Key entity identity. */
    private static final String KEY_IDENTITY = "identity";

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();

    /** Authentication utilities. */
    private static MockAuthenticationUtils authutils;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.ECC, false);
        encoder = ctx.getMslEncoderFactory();
        final MockEccStore eccStore = new MockEccStore();
        eccStore.addPublicKey(MockEccAuthenticationFactory.ECC_PUBKEY_ID, MockEccAuthenticationFactory.ECC_PUBKEY);
        authutils = new MockAuthenticationUtils();
        factory = new EccAuthenticationFactory(eccStore, authutils);
        ctx.addEntityAuthenticationFactory(factory);
    }
    
    @AfterClass
    public static void teardown() {
        factory = null;
        authutils = null;
        encoder = null;
        ctx = null;
    }
    
    @After
    public void reset() {
        authutils.reset();
    }
    
    @Test
    public void createData() throws MslEncodingException, MslEntityAuthException, JSONException, MslCryptoException, MslEncoderException {
        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final MslObject entityAuthMo = data.getAuthData(encoder, ENCODER_FORMAT);
        
        final EntityAuthenticationData authdata = factory.createData(ctx, entityAuthMo);
        assertNotNull(authdata);
        assertTrue(authdata instanceof EccAuthenticationData);

        final MslObject dataMo = MslTestUtils.toMslObject(encoder, data);
        final MslObject authdataMo = MslTestUtils.toMslObject(encoder, authdata);
        assertTrue(MslEncoderUtils.equalObjects(dataMo, authdataMo));
    }
    
    @Test
    public void encodeException() throws MslEncodingException, MslEntityAuthException, MslCryptoException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final MslObject entityAuthMo = data.getAuthData(encoder, ENCODER_FORMAT);
        entityAuthMo.remove(KEY_IDENTITY);
        factory.createData(ctx, entityAuthMo);
    }
    
    @Test
    public void cryptoContext() throws MslEntityAuthException, MslCryptoException {
        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, data);
        assertNotNull(cryptoContext);
    }

    @Test
    public void unknownKeyId() throws MslEntityAuthException, MslCryptoException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ECC_PUBLICKEY_NOT_FOUND);

        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, "x");
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void localCryptoContext() throws MslCryptoException, MslEntityAuthException {
        final MockEccStore eccStore = new MockEccStore();
        eccStore.addPrivateKey(MockEccAuthenticationFactory.ECC_PUBKEY_ID, MockEccAuthenticationFactory.ECC_PRIVKEY);
        final EntityAuthenticationFactory factory = new EccAuthenticationFactory(MockEccAuthenticationFactory.ECC_PUBKEY_ID, eccStore, authutils);
        
        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, data);
        
        final byte[] plaintext = new byte[16];
        ctx.getRandom().nextBytes(plaintext);
        cryptoContext.sign(plaintext, encoder, ENCODER_FORMAT);
    }
    
    @Test
    public void missingPrivateKey() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ECC_PRIVATEKEY_NOT_FOUND);
        
        final MockEccStore eccStore = new MockEccStore();
        eccStore.addPublicKey(MockEccAuthenticationFactory.ECC_PUBKEY_ID, MockEccAuthenticationFactory.ECC_PUBKEY);
        final EntityAuthenticationFactory factory = new EccAuthenticationFactory(MockEccAuthenticationFactory.ECC_PUBKEY_ID, eccStore, authutils);
        
        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, MockEccAuthenticationFactory.ECC_PUBKEY_ID);
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void revoked() throws MslEntityAuthException, MslCryptoException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITY_REVOKED);

        authutils.revokeEntity(MockEccAuthenticationFactory.ECC_ESN);
        final EccAuthenticationData data = new EccAuthenticationData(MockEccAuthenticationFactory.ECC_ESN, "x");
        factory.getCryptoContext(ctx, data);
    }
    
    /** MSL context. */
    private static MockMslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Entity authentication factory. */
    private static EntityAuthenticationFactory factory;
}
