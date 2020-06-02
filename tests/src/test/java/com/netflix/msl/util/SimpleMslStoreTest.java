/**
 * Copyright (c) 2012-2020 Netflix, Inc.  All rights reserved.
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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.Collection;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslConstants;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslMasterTokenException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.NullCryptoContext;
import com.netflix.msl.crypto.SessionCryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;

/**
 * Simple MSL store unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class SimpleMslStoreTest {
    private static final String KEYSET_ID = "keyset";
    private static final String USER_ID = "userid";
    
    /** Maximum number of randomly generated tokens. */
    private static final int MAX_TOKENS = 3;
    
    /** Stress test pool shutdown timeout in milliseconds. */
    private static final int STRESS_TIMEOUT_MILLIS = 3000;
    
    /**
     * @param c1 first collection.
     * @param c2 second collection.
     * @return true if each collection contain all elements found in the other.
     */
    private static boolean equal(final Collection<? extends Object> c1, final Collection<? extends Object> c2) {
        return c1.containsAll(c2) && c2.containsAll(c1);
    }

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.NONE, false);
    }
    
    @AfterClass
    public static void teardown() {
        ctx = null;
    }
    
    @Before
    public void createStore() {
        store = new SimpleMslStore();
    }
    
    @After
    public void destroyStore() {
        store = null;
    }
    
    @Test
    public void storeCryptoContext() throws MslEncodingException, MslCryptoException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        assertNull(store.getCryptoContext(masterToken));
        
        final ICryptoContext cc1 = new SymmetricCryptoContext(ctx, KEYSET_ID, masterToken.getEncryptionKey(), masterToken.getSignatureKey(), null);
        store.setCryptoContext(masterToken, cc1);
        final ICryptoContext cc2 = store.getCryptoContext(masterToken);
        assertNotNull(cc2);
        assertSame(cc1, cc2);
        assertEquals(masterToken, store.getMasterToken());
    }
    
    @Test
    public void replaceCryptoContext() throws MslEncodingException, MslCryptoException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cc1 = new SymmetricCryptoContext(ctx, KEYSET_ID, masterToken.getEncryptionKey(), masterToken.getSignatureKey(), null);
        final ICryptoContext cc2 = new NullCryptoContext();
        
        store.setCryptoContext(masterToken, cc1);
        final ICryptoContext cc3 = store.getCryptoContext(masterToken);
        assertSame(cc1, cc3);
        assertNotSame(cc2, cc3);
        
        store.setCryptoContext(masterToken, cc2);
        final ICryptoContext cc4 = store.getCryptoContext(masterToken);
        assertNotSame(cc1, cc4);
        assertSame(cc2, cc4);
        assertEquals(masterToken, store.getMasterToken());
    }
    
    @Test
    public void removeCryptoContext() throws MslEncodingException, MslCryptoException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        
        store.setCryptoContext(masterToken, cryptoContext);
        store.removeCryptoContext(masterToken);
        assertNull(store.getMasterToken());
        assertNull(store.getCryptoContext(masterToken));
    }
    
    @Test
    public void clearCryptoContext() throws MslEncodingException, MslCryptoException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cc1 = new SymmetricCryptoContext(ctx, KEYSET_ID, masterToken.getEncryptionKey(), masterToken.getSignatureKey(), null);
        store.setCryptoContext(masterToken, cc1);
        store.clearCryptoContexts();
        assertNull(store.getCryptoContext(masterToken));
        assertNull(store.getMasterToken());
    }
    
    @Test
    public void twoCryptoContexts() throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        final MasterToken mtA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken mtB = MslTestUtils.getMasterToken(ctx, 2, 1);
        
        final ICryptoContext ccMtA1 = new SessionCryptoContext(ctx, mtA);
        final ICryptoContext ccMtB1 = new SessionCryptoContext(ctx, mtB);
        store.setCryptoContext(mtA, ccMtA1);
        store.setCryptoContext(mtB, ccMtB1);
        
        final ICryptoContext ccMtA2 = store.getCryptoContext(mtA);
        assertNotNull(ccMtA2);
        assertSame(ccMtA1, ccMtA2);
        
        final ICryptoContext ccMtB2 = store.getCryptoContext(mtB);
        assertNotNull(ccMtB2);
        assertSame(ccMtB1, ccMtB2);
        
        assertEquals(mtB, store.getMasterToken());
    }
    
    @Test
    public void replaceTwoCryptoContexts() throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        final MasterToken mtA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken mtB = MslTestUtils.getMasterToken(ctx, 2, 1);
        
        final ICryptoContext ccMtA1 = new SessionCryptoContext(ctx, mtA);
        final ICryptoContext ccMtB1 = new SessionCryptoContext(ctx, mtB);
        store.setCryptoContext(mtA, ccMtA1);
        store.setCryptoContext(mtB, ccMtB1);
        assertEquals(mtB, store.getMasterToken());
        
        final ICryptoContext ccNull = new NullCryptoContext();
        store.setCryptoContext(mtA, ccNull);
        
        final ICryptoContext ccMtA2 = store.getCryptoContext(mtA);
        assertNotNull(ccMtA2);
        assertNotSame(ccMtA1, ccMtA2);
        assertSame(ccNull, ccMtA2);
        
        final ICryptoContext ccMtB2 = store.getCryptoContext(mtB);
        assertNotNull(ccMtB2);
        assertSame(ccMtB1, ccMtB2);

        assertEquals(mtB, store.getMasterToken());
    }
    
    @Test
    public void clearTwoCryptoContexts() throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        final MasterToken mtA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken mtB = MslTestUtils.getMasterToken(ctx, 2, 1);
        
        final ICryptoContext ccMtA1 = new SessionCryptoContext(ctx, mtA);
        final ICryptoContext ccMtB1 = new SessionCryptoContext(ctx, mtB);
        store.setCryptoContext(mtA, ccMtA1);
        store.setCryptoContext(mtB, ccMtB1);
        
        store.clearCryptoContexts();
        assertNull(store.getCryptoContext(mtA));
        assertNull(store.getCryptoContext(mtB));
        assertNull(store.getMasterToken());
    }
    
    @Test
    public void removeTwoCryptoContexts() throws MslEncodingException, MslCryptoException, MslMasterTokenException {
        final MasterToken mtA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken mtB = MslTestUtils.getMasterToken(ctx, 2, 1);
        
        final ICryptoContext ccMtA1 = new SessionCryptoContext(ctx, mtA);
        final ICryptoContext ccMtB1 = new SessionCryptoContext(ctx, mtB);
        store.setCryptoContext(mtA, ccMtA1);
        store.setCryptoContext(mtB, ccMtB1);
        
        store.removeCryptoContext(mtA);
        assertNull(store.getCryptoContext(mtA));
        assertEquals(ccMtB1, store.getCryptoContext(mtB));
    }
    
    /**
     * Crypto context add/remove stress test runner.
     * 
     * Randomly adds or removes a crypto context for one of many master tokens
     * (by master token entity identity). Also iterates through the set crypto
     * contexts.
     */
    private static class CryptoContextStressor implements Runnable {
        /**
         * Create a new crypto context stressor.
         * 
         * @param ctx MSL context.
         * @param store MSL store.
         * @param count the number of master token identities to stress.
         */
        public CryptoContextStressor(final MslContext ctx, final MslStore store, final int count) {
            this.ctx = ctx;
            this.store = store;
            this.count = count;
        }
        
        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        @Override
        public void run() {
            final Random r = new Random();
            
            try {
                for (int i = 0; i < 10 * count; ++i) {
                    final int tokenIndex = r.nextInt(count);
                    final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, tokenIndex, 1);
                    final int option = r.nextInt(4);
                    switch (option) {
                        case 0:
                            store.setCryptoContext(masterToken, null);
                            break;
                        case 1:
                            final ICryptoContext cryptoContext = new SessionCryptoContext(ctx, masterToken);
                            store.setCryptoContext(masterToken, cryptoContext);
                            break;
                        case 2:
                            store.getCryptoContext(masterToken);
                            break;
                        case 3:
                            store.removeCryptoContext(masterToken);
                            break;
                    }
                }
            } catch (final MslMasterTokenException e) {
                throw new MslInternalException("Unexpected master token exception.", e);
            } catch (final MslEncodingException e) {
                throw new MslInternalException("Unexpected master token encoding exception.", e);
            } catch (final MslCryptoException e) {
                throw new MslInternalException("Unexpected master token creation exception.", e);
            }
        }
        
        /** MSL context. */
        private final MslContext ctx;
        /** MSL store. */
        private final MslStore store;
        /** Number of crypto context identities. */
        private final int count;
    }
    
    @Test
    public void stressCryptoContexts() throws InterruptedException, MslEncodingException, MslCryptoException {
        final ExecutorService service = Executors.newCachedThreadPool();
        for (int i = 0; i < 10 * MAX_TOKENS; ++i) {
            service.execute(new CryptoContextStressor(ctx, store, MAX_TOKENS));
        }
        service.shutdown();
        assertTrue(service.awaitTermination(STRESS_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
    }
    
    @Test
    public void nonReplayableId() throws MslEncodingException, MslCryptoException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        
        for (int i = 1; i < 10; ++i)
            assertEquals(i, store.getNonReplayableId(masterToken));
    }
    
    @Ignore
    @Test
    public void wrappedNonReplayableId() throws MslEncodingException, MslCryptoException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        
        for (long i = 1; i < MslConstants.MAX_LONG_VALUE; ++i)
            store.getNonReplayableId(masterToken);
        assertEquals(MslConstants.MAX_LONG_VALUE, store.getNonReplayableId(masterToken));
        assertEquals(0, store.getNonReplayableId(masterToken));
        assertEquals(1, store.getNonReplayableId(masterToken));
    }
    
    @Test
    public void twoNonReplayableIds() throws MslEncodingException, MslCryptoException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        
        for (int i = 1; i < 10; ++i) {
            assertEquals(i, store.getNonReplayableId(masterTokenA));
            assertEquals(i, store.getNonReplayableId(masterTokenB));
        }
    }

    @Test
    public void addUserIdToken() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdToken);
        
        assertEquals(userIdToken, store.getUserIdToken(USER_ID));
        assertNull(store.getUserIdToken(USER_ID + "x"));
    }
    
    @Test
    public void removeUserIdToken() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdToken);
        
        store.removeUserIdToken(userIdToken);
        assertNull(store.getUserIdToken(USER_ID));
    }
    
    @Test
    public void replaceUserIdToken() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER);

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdTokenA);
        store.addUserIdToken(USER_ID, userIdTokenB);
        assertEquals(userIdTokenB, store.getUserIdToken(USER_ID));
    }
    
    @Test
    public void twoUserIdTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER);

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        
        assertEquals(userIdTokenA, store.getUserIdToken(userIdA));
        assertEquals(userIdTokenB, store.getUserIdToken(userIdB));
    }
    
    @Test
    public void replaceTwoUserIdTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER);
        
        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        
        final UserIdToken userIdTokenC = MslTestUtils.getUserIdToken(ctx, masterToken, 3, MockEmailPasswordAuthenticationFactory.USER);
        store.addUserIdToken(userIdA, userIdTokenC);
        assertEquals(userIdTokenC, store.getUserIdToken(userIdA));
        assertEquals(userIdTokenB, store.getUserIdToken(userIdB));
    }
    
    @Test
    public void removeTwoUserIdTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER);

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);

        store.removeUserIdToken(userIdTokenA);
        assertNull(store.getUserIdToken(userIdA));
        assertEquals(userIdTokenB, store.getUserIdToken(userIdB));
    }
    
    @Test
    public void clearUserIdTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER);

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        
        store.clearUserIdTokens();
        assertNull(store.getUserIdToken(userIdA));
        assertNull(store.getUserIdToken(userIdB));
    }

    @Test
    public void unknownMasterTokenUserIdToken() throws MslEncodingException, MslCryptoException, MslException {
        thrown.expect(MslException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_MASTERTOKEN_NOT_FOUND);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        
        store.addUserIdToken(USER_ID, userIdToken);
    }
    
    @Test
    public void removeMasterTokenSameSerialNumberUserIdTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 2, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final String userIdC = USER_ID + "C";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterTokenA, 2, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenC = MslTestUtils.getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory.USER);

        store.setCryptoContext(masterTokenA, cryptoContext);
        store.setCryptoContext(masterTokenB, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        store.addUserIdToken(userIdC, userIdTokenC);

        // We still have a master token with serial number 1 so no user ID
        // tokens should be deleted.
        store.removeCryptoContext(masterTokenA);
        assertEquals(userIdTokenA, store.getUserIdToken(userIdA));
        assertEquals(userIdTokenB, store.getUserIdToken(userIdB));
        assertEquals(userIdTokenC, store.getUserIdToken(userIdC));
    }
    
    @Test
    public void removeMasterTokenReissuedUserIdTokens() throws MslEncodingException, MslCryptoException, MslException {
        // Master token B has a new serial number, to invalidate the old master
        // token and its user ID tokens.
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final String userIdC = USER_ID + "C";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterTokenA, 2, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenC = MslTestUtils.getUserIdToken(ctx, masterTokenB, 1, MockEmailPasswordAuthenticationFactory.USER);

        store.setCryptoContext(masterTokenA, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        store.setCryptoContext(masterTokenB, cryptoContext);
        store.addUserIdToken(userIdC, userIdTokenC);

        // All of master token A's user ID tokens should be deleted.
        store.removeCryptoContext(masterTokenA);
        assertNull(store.getUserIdToken(userIdA));
        assertNull(store.getUserIdToken(userIdB));
        assertEquals(userIdTokenC, store.getUserIdToken(userIdC));
    }
    
    @Test
    public void clearCryptoContextsUserIdTokens() throws MslEncodingException, MslCryptoException, MslException {
     // Master token B has a new serial number, to invalidate the old master
        // token and its user ID tokens.
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory.USER);

        store.setCryptoContext(masterTokenA, cryptoContext);
        store.setCryptoContext(masterTokenB, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);

        // All user ID tokens should be deleted.
        store.clearCryptoContexts();
        assertNull(store.getUserIdToken(userIdA));
        assertNull(store.getUserIdToken(userIdB));
    }

    /**
     * User ID token add/remove stress test runner.
     * 
     * Randomly adds or removes user ID tokens. Also iterates through the user
     * ID tokens.
     */
    private static class UserIdTokenStressor implements Runnable {
        /**
         * Create a new service token stressor.
         * 
         * @param ctx MSL context.
         * @param store MSL store.
         * @param count the number of master token and user ID tokens to create
         *        combinations of.
         */
        public UserIdTokenStressor(final MslContext ctx, final MslStore store, final int count) {
            this.ctx = ctx;
            this.store = store;
            this.count = count;
        }
        
        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        @Override
        public void run() {
            final Random r = new Random();
            
            try {
                for (int i = 0; i < 10 * count; ++i) {
                    final int tokenIndex = r.nextInt(count);
                    final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, tokenIndex, 1);
                    final long userId = r.nextInt(count);
                    final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, userId, MockEmailPasswordAuthenticationFactory.USER);

                    final int option = r.nextInt(3);
                    switch (option) {
                        case 0:
                        {
                            store.setCryptoContext(masterToken, new NullCryptoContext());
                            store.addUserIdToken(USER_ID + userId, userIdToken);
                            break;
                        }
                        case 1:
                        {
                            store.getUserIdToken(USER_ID + userId);
                            break;
                        }
                        case 2:
                        {
                            store.removeUserIdToken(userIdToken);
                            break;
                        }
                    }
                }
            } catch (final MslMasterTokenException e) {
                throw new MslInternalException("Unexpected master token exception.", e);
            } catch (final MslEncodingException e) {
                throw new MslInternalException("Unexpected master token encoding exception.", e);
            } catch (final MslCryptoException e) {
                throw new MslInternalException("Unexpected master token creation exception.", e);
            } catch (final MslException e) {
                throw new MslInternalException("Master token / user ID token service token query mismatch.", e);
            }
        }
        
        /** MSL context. */
        private final MslContext ctx;
        /** MSL store. */
        private final MslStore store;
        /** Number of master token and user ID token identities. */
        private final int count;
    }
    
    @Test
    public void stressUserIdTokens() throws InterruptedException {
        final ExecutorService service = Executors.newCachedThreadPool();
        for (int i = 0; i < 10 * MAX_TOKENS; ++i) {
            service.execute(new UserIdTokenStressor(ctx, store, MAX_TOKENS));
        }
        service.shutdown();
        assertTrue(service.awaitTermination(STRESS_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
    }
    
    @Test
    public void masterBoundServiceTokens() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> tokens = MslTestUtils.getServiceTokens(ctx, masterToken, null);
        
        store.setCryptoContext(masterToken, cryptoContext);
        
        final Set<ServiceToken> emptyTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(emptyTokens);
        assertEquals(0, emptyTokens.size());
        
        store.addServiceTokens(tokens);
        final Set<ServiceToken> storedTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(storedTokens);
        assertTrue(equal(tokens, storedTokens));
    }
    
    @Test
    public void missingMasterTokenAddServiceTokens() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final Set<ServiceToken> tokens = MslTestUtils.getServiceTokens(ctx, masterToken, null);

        MslException exception = null;
        try {
            store.addServiceTokens(tokens);
        } catch (final MslException e) {
            exception = e;
        }
        assertNotNull(exception);

        final Set<ServiceToken> emptyTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(emptyTokens);
        assertEquals(0, emptyTokens.size());
    }
    
    @Test
    public void userBoundServiceTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> tokens = MslTestUtils.getServiceTokens(ctx, masterToken, userIdToken);
        
        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdToken);
        
        final Set<ServiceToken> emptyTokens = store.getServiceTokens(masterToken, userIdToken);
        assertNotNull(emptyTokens);
        assertEquals(0, emptyTokens.size());
        
        store.addServiceTokens(tokens);
        final Set<ServiceToken> storedTokens = store.getServiceTokens(masterToken, userIdToken);
        assertNotNull(storedTokens);
        assertTrue(equal(tokens, storedTokens));
    }
    
    @Test
    public void missingUserIdTokenAddServiceTokens() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> tokens = MslTestUtils.getServiceTokens(ctx, masterToken, userIdToken);

        store.setCryptoContext(masterToken, cryptoContext);

        MslException exception = null;
        try {
            store.addServiceTokens(tokens);
        } catch (final MslException e) {
            exception = e;
        }
        assertNotNull(exception);

        final Set<ServiceToken> emptyTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(emptyTokens);
        assertEquals(0, emptyTokens.size());
    }
    
    @Test
    public void unboundServiceTokens() throws MslException {
        final Set<ServiceToken> tokens = MslTestUtils.getServiceTokens(ctx, null, null);
        
        final Set<ServiceToken> emptyTokens = store.getServiceTokens(null, null);
        assertNotNull(emptyTokens);
        assertEquals(0, emptyTokens.size());
        
        store.addServiceTokens(tokens);
        final Set<ServiceToken> storedTokens = store.getServiceTokens(null, null);
        assertNotNull(storedTokens);
        assertTrue(equal(tokens, storedTokens));
    }
    
    @Test
    public void removeMasterBoundServiceTokens() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> masterBoundTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken);
        final Set<ServiceToken> userBoundTokens = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken);
        final Set<ServiceToken> unboundTokens = MslTestUtils.getServiceTokens(ctx, null, null);
        
        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdToken);
        store.addServiceTokens(masterBoundTokens);
        store.addServiceTokens(userBoundTokens);
        store.addServiceTokens(unboundTokens);
        
        store.removeServiceTokens(null, masterToken, null);
        
        // This should only return the unbound tokens.
        final Set<ServiceToken> storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(storedMasterBoundTokens);
        assertTrue(equal(unboundTokens, storedMasterBoundTokens));
        
        // This should only return the unbound and user-bound tokens.
        final Set<ServiceToken> unboundAndUserBoundTokens = new HashSet<ServiceToken>();
        unboundAndUserBoundTokens.addAll(unboundTokens);
        unboundAndUserBoundTokens.addAll(userBoundTokens);
        final Set<ServiceToken> storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
        assertTrue(equal(unboundAndUserBoundTokens, storedUserBoundTokens));
        
        // This should only return the unbound tokens.
        final Set<ServiceToken> storedUnboundTokens = store.getServiceTokens(null, null);
        assertNotNull(storedUnboundTokens);
        assertTrue(equal(unboundTokens, storedUnboundTokens));
    }
    
    @Test
    public void removeUserBoundServiceTokens() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> masterBoundTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken);
        final Set<ServiceToken> userBoundTokens = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken);
        final Set<ServiceToken> unboundTokens = MslTestUtils.getServiceTokens(ctx, null, null);
        
        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdToken);
        store.addServiceTokens(masterBoundTokens);
        store.addServiceTokens(userBoundTokens);
        store.addServiceTokens(unboundTokens);
        
        store.removeServiceTokens(null, null, userIdToken);
        
        // This should only return the unbound and master bound-only tokens.
        final Set<ServiceToken> storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(storedMasterBoundTokens);
        final Set<ServiceToken> unboundAndMasterBoundTokens = new HashSet<ServiceToken>();
        unboundAndMasterBoundTokens.addAll(unboundTokens);
        unboundAndMasterBoundTokens.addAll(masterBoundTokens);
        assertTrue(equal(unboundAndMasterBoundTokens, storedMasterBoundTokens));
        
        // This should only return the unbound and master bound-only tokens.
        final Set<ServiceToken> storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
        assertNotNull(storedUserBoundTokens);
        assertTrue(equal(unboundAndMasterBoundTokens, storedUserBoundTokens));
        
        // This should only return the unbound tokens.
        final Set<ServiceToken> storedUnboundTokens = store.getServiceTokens(null, null);
        assertNotNull(storedUnboundTokens);
        assertTrue(equal(unboundTokens, storedUnboundTokens));
    }
    
    @Test
    public void removeNoServiceTokens() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> masterBoundTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken);
        final Set<ServiceToken> userBoundTokens = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken);
        final Set<ServiceToken> unboundTokens = MslTestUtils.getServiceTokens(ctx, null, null);
        
        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdToken);
        store.addServiceTokens(masterBoundTokens);
        store.addServiceTokens(userBoundTokens);
        store.addServiceTokens(unboundTokens);
        
        store.removeServiceTokens(null, null, null);
        
        // This should only return the unbound and master bound tokens.
        final Set<ServiceToken> storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(storedMasterBoundTokens);
        final Set<ServiceToken> unboundAndMasterBoundTokens = new HashSet<ServiceToken>();
        unboundAndMasterBoundTokens.addAll(unboundTokens);
        unboundAndMasterBoundTokens.addAll(masterBoundTokens);
        assertTrue(equal(unboundAndMasterBoundTokens, storedMasterBoundTokens));
        
        // This should return all of the tokens.
        final Set<ServiceToken> storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
        assertNotNull(storedUserBoundTokens);
        final Set<ServiceToken> allTokens = new HashSet<ServiceToken>();
        allTokens.addAll(unboundTokens);
        allTokens.addAll(userBoundTokens);
        allTokens.addAll(masterBoundTokens);
        assertTrue(equal(allTokens, storedUserBoundTokens));
        
        // This should only return the unbound tokens.
        final Set<ServiceToken> storedUnboundTokens = store.getServiceTokens(null, null);
        assertNotNull(storedUnboundTokens);
        assertTrue(equal(unboundTokens, storedUnboundTokens));
    }
    
    @Test
    public void removeNamedServiceTokens() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> masterBoundTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken);
        final Set<ServiceToken> userBoundTokens = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken);
        final Set<ServiceToken> unboundTokens = MslTestUtils.getServiceTokens(ctx, null, null);

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdToken);
        store.addServiceTokens(masterBoundTokens);
        store.addServiceTokens(userBoundTokens);
        store.addServiceTokens(unboundTokens);
        
        final Set<ServiceToken> allTokens = new HashSet<ServiceToken>();
        allTokens.addAll(masterBoundTokens);
        allTokens.addAll(userBoundTokens);
        allTokens.addAll(unboundTokens);
        
        final Random random = new Random();
        final Set<ServiceToken> removedTokens = new HashSet<ServiceToken>();
        for (final ServiceToken token : allTokens) {
            if (random.nextBoolean()) continue;
            store.removeServiceTokens(token.getName(), token.isMasterTokenBound() ? masterToken : null, token.isUserIdTokenBound() ? userIdToken : null);
            removedTokens.add(token);
        }
        
        // This should only return tokens that haven't been removed.
        final Set<ServiceToken> storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(storedMasterBoundTokens);
        assertFalse(storedMasterBoundTokens.removeAll(removedTokens));
        
        // This should only return tokens that haven't been removed.
        final Set<ServiceToken> storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
        assertNotNull(storedUserBoundTokens);
        assertFalse(storedUserBoundTokens.removeAll(removedTokens));
        
        // This should only return tokens that haven't been removed.
        final Set<ServiceToken> storedUnboundTokens = store.getServiceTokens(null, null);
        assertNotNull(storedUnboundTokens);
        assertFalse(storedUnboundTokens.removeAll(removedTokens));
    }
    
    @Test
    public void clearServiceTokens() throws MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final Set<ServiceToken> masterBoundTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken);
        final Set<ServiceToken> userBoundTokens = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdToken);
        final Set<ServiceToken> unboundTokens = MslTestUtils.getServiceTokens(ctx, null, null);

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(USER_ID, userIdToken);
        store.addServiceTokens(masterBoundTokens);
        store.addServiceTokens(userBoundTokens);
        store.addServiceTokens(unboundTokens);
        
        store.clearServiceTokens();

        final Set<ServiceToken> storedMasterBoundTokens = store.getServiceTokens(masterToken, null);
        assertNotNull(storedMasterBoundTokens);
        assertEquals(0, storedMasterBoundTokens.size());
        final Set<ServiceToken> storedUserBoundTokens = store.getServiceTokens(masterToken, userIdToken);
        assertNotNull(storedUserBoundTokens);
        assertEquals(0, storedUserBoundTokens.size());
        final Set<ServiceToken> storedUnboundTokens = store.getServiceTokens(null, null);
        assertNotNull(storedUnboundTokens);
        assertEquals(0, storedUserBoundTokens.size());
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

    @Test
    public void removeMasterTokenSameSerialNumberServiceTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 2, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory.USER);
        final Set<ServiceToken> masterBoundServiceTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterTokenA);
        final Set<ServiceToken> serviceTokensA = MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA);
        final Set<ServiceToken> serviceTokensB = MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB);

        store.setCryptoContext(masterTokenA, cryptoContext);
        store.setCryptoContext(masterTokenB, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        store.addServiceTokens(masterBoundServiceTokens);
        store.addServiceTokens(serviceTokensA);
        store.addServiceTokens(serviceTokensB);

        // We still have a master token with serial number 1 so no service
        // tokens should have been deleted.
        store.removeCryptoContext(masterTokenA);
        final Set<ServiceToken> storedServiceTokensA = store.getServiceTokens(masterTokenB, userIdTokenA);
        final Set<ServiceToken> storedServiceTokensB = store.getServiceTokens(masterTokenB, userIdTokenB);
        final Set<ServiceToken> expectedServiceTokensA = new HashSet<ServiceToken>(masterBoundServiceTokens);
        expectedServiceTokensA.addAll(serviceTokensA);
        assertEquals(expectedServiceTokensA, storedServiceTokensA);
        final Set<ServiceToken> expectedServiceTokensB = new HashSet<ServiceToken>(masterBoundServiceTokens);
        expectedServiceTokensB.addAll(serviceTokensB);
        assertEquals(expectedServiceTokensB, storedServiceTokensB);
    }
    
    @Test
    public void removeMasterTokenReissuedServiceTokens() throws MslEncodingException, MslCryptoException, MslException {
        // Master token B has a new serial number, to invalidate the old master
        // token and its user ID tokens.
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory.USER);
        final Set<ServiceToken> masterBoundServiceTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterTokenA);
        final Set<ServiceToken> serviceTokensA = MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA);
        final Set<ServiceToken> serviceTokensB = MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB);

        store.setCryptoContext(masterTokenA, cryptoContext);
        store.setCryptoContext(masterTokenB, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        store.addServiceTokens(masterBoundServiceTokens);
        store.addServiceTokens(serviceTokensA);
        store.addServiceTokens(serviceTokensB);

        // All of master token A's user ID tokens should be deleted.
        store.removeCryptoContext(masterTokenA);
        assertTrue(store.getServiceTokens(masterTokenA, userIdTokenA).isEmpty());
        final Set<ServiceToken> storedServiceTokensB = store.getServiceTokens(masterTokenB, userIdTokenB);
        assertEquals(serviceTokensB, storedServiceTokensB);
    }
    
    @Test
    public void clearCryptoContextsServiceTokens() throws MslEncodingException, MslCryptoException, MslException {
        // Master token B has a new serial number, to invalidate the old master
        // token and its user ID tokens.
        final MasterToken masterTokenA = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MasterToken masterTokenB = MslTestUtils.getMasterToken(ctx, 1, 2);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterTokenA, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterTokenB, 2, MockEmailPasswordAuthenticationFactory.USER);
        final Set<ServiceToken> unboundServiceTokens = MslTestUtils.getServiceTokens(ctx, null, null);
        final Set<ServiceToken> serviceTokensA = MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenA, userIdTokenA);
        final Set<ServiceToken> serviceTokensB = MslTestUtils.getUserBoundServiceTokens(ctx, masterTokenB, userIdTokenB);

        store.setCryptoContext(masterTokenA, cryptoContext);
        store.setCryptoContext(masterTokenB, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        store.addServiceTokens(unboundServiceTokens);
        store.addServiceTokens(serviceTokensA);
        store.addServiceTokens(serviceTokensB);

        // All bound service tokens should be deleted.
        store.clearCryptoContexts();
        assertEquals(unboundServiceTokens, store.getServiceTokens(masterTokenA, userIdTokenA));
        assertEquals(unboundServiceTokens, store.getServiceTokens(masterTokenB, userIdTokenB));
        final Set<ServiceToken> storedServiceTokens = store.getServiceTokens(null, null);
        assertEquals(unboundServiceTokens, storedServiceTokens);
    }
    
    @Test
    public void removeUserIdTokenServiceTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER);
        final Set<ServiceToken> masterBoundServiceTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken);
        final Set<ServiceToken> serviceTokensA = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdTokenA);
        final Set<ServiceToken> serviceTokensB = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdTokenB);

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        store.addServiceTokens(masterBoundServiceTokens);
        store.addServiceTokens(serviceTokensA);
        store.addServiceTokens(serviceTokensB);
        
        // We should still have all the master token bound and user ID token B
        // bound service tokens.
        store.removeUserIdToken(userIdTokenA);
        final Set<ServiceToken> storedServiceTokens = store.getServiceTokens(masterToken, userIdTokenB);
        final Set<ServiceToken> expectedServiceTokens = new HashSet<ServiceToken>(masterBoundServiceTokens);
        expectedServiceTokens.addAll(serviceTokensB);
        assertEquals(expectedServiceTokens, storedServiceTokens);
    }
    
    @Test
    public void clearUserIdTokensServiceTokens() throws MslEncodingException, MslCryptoException, MslException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final ICryptoContext cryptoContext = new NullCryptoContext();
        final String userIdA = USER_ID + "A";
        final String userIdB = USER_ID + "B";
        final UserIdToken userIdTokenA = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserIdToken userIdTokenB = MslTestUtils.getUserIdToken(ctx, masterToken, 2, MockEmailPasswordAuthenticationFactory.USER);
        final Set<ServiceToken> masterBoundServiceTokens = MslTestUtils.getMasterBoundServiceTokens(ctx, masterToken);
        final Set<ServiceToken> serviceTokensA = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdTokenA);
        final Set<ServiceToken> serviceTokensB = MslTestUtils.getUserBoundServiceTokens(ctx, masterToken, userIdTokenB);

        store.setCryptoContext(masterToken, cryptoContext);
        store.addUserIdToken(userIdA, userIdTokenA);
        store.addUserIdToken(userIdB, userIdTokenB);
        store.addServiceTokens(masterBoundServiceTokens);
        store.addServiceTokens(serviceTokensA);
        store.addServiceTokens(serviceTokensB);
        
        // Only the master token bound service tokens should be left.
        store.clearUserIdTokens();
        final Set<ServiceToken> storedServiceTokens = store.getServiceTokens(masterToken, userIdTokenB);
        assertEquals(masterBoundServiceTokens, storedServiceTokens);
    }
    
    /**
     * Service token add/remove stress test runner.
     * 
     * Randomly adds or removes service tokens in combinations of unbound,
     * master token bound, and user ID token bound Also iterates through the
     * service tokens.
     */
    private static class ServiceTokenStressor implements Runnable {
        /**
         * Create a new service token stressor.
         * 
         * @param ctx MSL context.
         * @param store MSL store.
         * @param count the number of master token and user ID tokens to create
         *        combinations of.
         */
        public ServiceTokenStressor(final MslContext ctx, final MslStore store, final int count) {
            this.ctx = ctx;
            this.store = store;
            this.count = count;
        }
        
        /* (non-Javadoc)
         * @see java.lang.Runnable#run()
         */
        @Override
        public void run() {
            final Random r = new Random();
            
            try {
                for (int i = 0; i < 10 * count; ++i) {
                    final int tokenIndex = r.nextInt(count);
                    final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, tokenIndex, 1);
                    final long userId = r.nextInt(count);
                    final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, userId, MockEmailPasswordAuthenticationFactory.USER);

                    final int option = r.nextInt(6);
                    switch (option) {
                        case 0:
                        {
                            final Set<ServiceToken> tokens = MslTestUtils.getServiceTokens(ctx, null, null);
                            store.addServiceTokens(tokens);
                            break;
                        }
                        case 1:
                        {
                            store.setCryptoContext(masterToken, new NullCryptoContext());
                            final Set<ServiceToken> tokens = MslTestUtils.getServiceTokens(ctx, masterToken, null);
                            store.addServiceTokens(tokens);
                            break;
                        }
                        case 2:
                        {
                            store.setCryptoContext(masterToken, new NullCryptoContext());
                            store.addUserIdToken(USER_ID + userId, userIdToken);
                            final Set<ServiceToken> tokens = MslTestUtils.getServiceTokens(ctx, masterToken, userIdToken);
                            store.addServiceTokens(tokens);
                            break;
                        }
                        case 3:
                        {
                            store.getServiceTokens(null, null);
                            break;
                        }
                        case 4:
                        {
                            store.getServiceTokens(masterToken, null);
                            break;
                        }
                        case 5:
                        {
                            store.getServiceTokens(masterToken, userIdToken);
                            break;
                        }
                    }
                }
            } catch (final MslMasterTokenException e) {
                throw new MslInternalException("Unexpected master token exception.", e);
            } catch (final MslEncodingException e) {
                throw new MslInternalException("Unexpected master token encoding exception.", e);
            } catch (final MslCryptoException e) {
                throw new MslInternalException("Unexpected master token creation exception.", e);
            } catch (final MslException e) {
                throw new MslInternalException("Master token / user ID token service token query mismatch.", e);
            }
        }
        
        /** MSL context. */
        private final MslContext ctx;
        /** MSL store. */
        private final MslStore store;
        /** Number of master token and user ID token identities. */
        private final int count;
    }
    
    @Test
    public void stressServiceTokens() throws InterruptedException {
        final ExecutorService service = Executors.newCachedThreadPool();
        for (int i = 0; i < 10 * MAX_TOKENS; ++i) {
            service.execute(new ServiceTokenStressor(ctx, store, MAX_TOKENS));
        }
        service.shutdown();
        assertTrue(service.awaitTermination(STRESS_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS));
    }
    
    /** MSL context. */
    private static MslContext ctx;
    
    /** MSL store. */
    private MslStore store;
}
