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
package com.netflix.msl.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.util.HashSet;
import java.util.Set;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.MockPresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationData;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MockTokenFactory;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;

/**
 * Null MSL store unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class NullMslStoreTest {
    private static final String TOKEN_NAME = "name";

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.NONE, false);
        factory = new MockTokenFactory();
        entityAuthData = new PresharedAuthenticationData(MockPresharedAuthenticationFactory.PSK_ESN);
    }
    
    @AfterClass
    public static void teardown() {
    	entityAuthData = null;
        factory = null;
        ctx = null;
    }
    
    @Before
    public void createStore() {
        store = new NullMslStore();
    }
    
    @After
    public void destroyStore() {
        store = null;
    }
    
    @Test
    public void cryptoContexts() throws MslException {
        final MasterToken masterToken = factory.createMasterToken(ctx, entityAuthData, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, null);
        assertNull(store.getCryptoContext(masterToken));
        
        final ICryptoContext cryptoContext = new NullCryptoContext();
        store.setCryptoContext(masterToken, cryptoContext);
        assertNull(store.getCryptoContext(masterToken));
        store.clearCryptoContexts();
    }
    
    @Test
    public void nonReplayableId() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = factory.createMasterToken(ctx, entityAuthData, MockPresharedAuthenticationFactory.KPE, MockPresharedAuthenticationFactory.KPH, null);
        for (int i = 0; i < 10; ++i)
            assertEquals(1, store.getNonReplayableId(masterToken));
    }
    
    @Test
    public void serviceTokens() throws MslException {
        assertEquals(0, store.getServiceTokens(null, null).size());
        
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final byte[] data = new byte[8];
        ctx.getRandom().nextBytes(data);
        final ServiceToken serviceToken = new ServiceToken(ctx, TOKEN_NAME, data, null, null, false, null, cryptoContext);
        final Set<ServiceToken> tokens = new HashSet<ServiceToken>();
        tokens.add(serviceToken);
        store.addServiceTokens(tokens);
        assertEquals(0, store.getServiceTokens(null, null).size());
        
        store.removeServiceTokens(TOKEN_NAME, null, null);
        store.clearServiceTokens();
    }
    
    @Test
    public void mismatchedGetServiceTokens() throws MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final MasterToken mismatchedMasterToken = MslTestUtils.getMasterToken(ctx, 2, 2);
        
        store.getServiceTokens(mismatchedMasterToken, userIdToken);
    }
    
    @Test
    public void missingMasterTokenGetServiceTokens() throws MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_NULL);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        
        store.getServiceTokens(null, userIdToken);
    }
    
    @Test
    public void mismatchedRemoveServiceTokens() throws MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final MasterToken mismatchedMasterToken = MslTestUtils.getMasterToken(ctx, 2, 2);
        
        store.removeServiceTokens(null, mismatchedMasterToken, userIdToken);
    }
    
    /** MSL context. */
    private static MslContext ctx;
    /** Token factory. */
    private static TokenFactory factory;
    /** Entity authentication data. */
    private static EntityAuthenticationData entityAuthData;
    
    /** MSL store. */
    private MslStore store;
}
