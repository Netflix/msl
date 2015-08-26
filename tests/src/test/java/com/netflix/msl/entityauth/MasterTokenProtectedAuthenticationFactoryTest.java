/**
 * Copyright (c) 2015 Netflix, Inc.  All rights reserved.
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
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.JsonUtils;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Master token protected authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MasterTokenProtectedAuthenticationFactoryTest {
    /** JSON key master token. */
    protected static final String KEY_MASTER_TOKEN = "mastertoken";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    private static final String IDENTITY = "identity";
    
    /** MSL context. */
    private static MockMslContext ctx;
    /** Authentication utilities. */
    private static MockAuthenticationUtils authutils;
    /** Entity authentication factory. */
    private static EntityAuthenticationFactory factory;

    /** Master token. */
    private static MasterToken masterToken;
    /** Encapsulated entity authentication data. */
    private static EntityAuthenticationData eAuthdata;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.NONE, false);
        authutils = new MockAuthenticationUtils();
        factory = new MasterTokenProtectedAuthenticationFactory(authutils);
        ctx.addEntityAuthenticationFactory(factory);
        
        masterToken = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        eAuthdata = new UnauthenticatedAuthenticationData(IDENTITY);
    }
    
    @AfterClass
    public static void teardown() {
        eAuthdata = null;
        masterToken = null;
        
        factory = null;
        authutils = null;
        ctx = null;
    }
    
    @After
    public void reset() {
        authutils.reset();
    }
    
    @Test
    public void createData() throws MslCryptoException, MslEntityAuthException, MslEncodingException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject entityAuthJO = data.getAuthData();
        
        final EntityAuthenticationData authdata = factory.createData(ctx, entityAuthJO);
        assertNotNull(authdata);
        assertTrue(authdata instanceof MasterTokenProtectedAuthenticationData);
        
        final JSONObject dataJo = new JSONObject(data.toJSONString());
        final JSONObject authdataJo = new JSONObject(authdata.toJSONString());
        assertTrue(JsonUtils.equals(dataJo, authdataJo));
    }
    
    @Test
    public void encodeException() throws MslCryptoException, MslEntityAuthException, MslEncodingException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.JSON_PARSE_ERROR);

        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final JSONObject entityAuthJO = data.getAuthData();
        entityAuthJO.remove(KEY_MASTER_TOKEN);
        factory.createData(ctx, entityAuthJO);
    }
    
    @Test
    public void cryptoContext() throws MslCryptoException, MslEntityAuthException {
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        final ICryptoContext cryptoContext = factory.getCryptoContext(ctx, data);
        assertNotNull(cryptoContext);
    }
    
    @Test
    public void unsupportedEncapsulatedScheme() throws MslEncodingException, MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITYAUTH_FACTORY_NOT_FOUND);
        
        final MockMslContext ctx = new MockMslContext(EntityAuthenticationScheme.NONE, false);
        ctx.removeEntityAuthenticationFactory(EntityAuthenticationScheme.NONE);
        
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void revoked() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.ENTITY_REVOKED);

        authutils.revokeEntity(IDENTITY);
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        factory.getCryptoContext(ctx, data);
    }
    
    @Test
    public void schemeNotPermitted() throws MslCryptoException, MslEntityAuthException {
        thrown.expect(MslEntityAuthException.class);
        thrown.expectMslError(MslError.INCORRECT_ENTITYAUTH_DATA);
        
        authutils.disallowScheme(IDENTITY, EntityAuthenticationScheme.MT_PROTECTED);
        final MasterTokenProtectedAuthenticationData data = new MasterTokenProtectedAuthenticationData(ctx, masterToken, eAuthdata);
        factory.getCryptoContext(ctx, data);
    }
}
