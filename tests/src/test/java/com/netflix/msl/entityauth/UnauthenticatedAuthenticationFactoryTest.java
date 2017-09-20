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
package com.netflix.msl.entityauth;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
 * Unauthenticated authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UnauthenticatedAuthenticationFactoryTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key entity identity. */
    private static final String KEY_IDENTITY = "identity";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    private static final String UNAUTHENTICATED_ESN = "MOCKUNAUTH-ESN";
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.NONE, false);
        encoder = ctx.getMslEncoderFactory();
        authutils = new MockAuthenticationUtils();
        factory = new UnauthenticatedAuthenticationFactory(authutils);
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
    public void createData() throws MslCryptoException, MslEncodingException, MslEntityAuthException, MslEncoderException {
        final UnauthenticatedAuthenticationData data = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        final MslObject entityAuthMo = data.getAuthData(encoder, ENCODER_FORMAT);
        
        final EntityAuthenticationData authdata = factory.createData(ctx, entityAuthMo);
        assertNotNull(authdata);
        assertTrue(authdata instanceof UnauthenticatedAuthenticationData);
        
        final MslObject dataMo = MslTestUtils.toMslObject(encoder, data);
        final MslObject authdataMo = MslTestUtils.toMslObject(encoder, authdata);
        assertTrue(MslEncoderUtils.equalObjects(dataMo, authdataMo));
    }
    
    @Test
    public void encodeException() throws MslCryptoException, MslEncodingException, MslEntityAuthException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final UnauthenticatedAuthenticationData data = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        final MslObject entityAuthJO = data.getAuthData(encoder, ENCODER_FORMAT);
        entityAuthJO.remove(KEY_IDENTITY);
        factory.createData(ctx, entityAuthJO);
    }
    
    @Test
    public void cryptoContext() throws MslCryptoException, MslEntityAuthException {
        final UnauthenticatedAuthenticationData data = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, data);
        assertNotNull(cryptoContext);
    }
    
    @Test
    public void notPermitted() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.INCORRECT_ENTITYAUTH_DATA);
        
        authutils.disallowScheme(UNAUTHENTICATED_ESN, EntityAuthenticationScheme.NONE);
        final UnauthenticatedAuthenticationData data = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void revoked() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITY_REVOKED);

        authutils.revokeEntity(UNAUTHENTICATED_ESN);
        final UnauthenticatedAuthenticationData data = new UnauthenticatedAuthenticationData(UNAUTHENTICATED_ESN);
        factory.getCryptoContext(ctx, data);
    }
    
    /** MSL context. */
    private static MockMslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Authentication utilities. */
    private static MockAuthenticationUtils authutils;
    /** Entity authentication factory. */
    private static EntityAuthenticationFactory factory;
}
