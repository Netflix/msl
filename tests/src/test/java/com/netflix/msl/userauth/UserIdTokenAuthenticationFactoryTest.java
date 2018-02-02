/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.userauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MockMslUser;
import com.netflix.msl.tokens.MockTokenFactory;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * User ID token user authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UserIdTokenAuthenticationFactoryTest {
    /** MSL encoder format. */
    private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key master token. */
    private static final String KEY_MASTER_TOKEN = "mastertoken";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    /** MSL context. */
    private static MockMslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Authentication utilities. */
    private static MockAuthenticationUtils authutils;
    /** User authentication factory. */
    private static UserAuthenticationFactory factory;
    /** Token factory. */
    private static MockTokenFactory tokenFactory;

    /** Master token. */
    private static MasterToken MASTER_TOKEN;
    /** User ID token. */
    private static UserIdToken USER_ID_TOKEN;

    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        authutils = new MockAuthenticationUtils();
        factory = new UserIdTokenAuthenticationFactory(authutils);
        ctx.addUserAuthenticationFactory(factory);
        tokenFactory = new MockTokenFactory();
        ctx.setTokenFactory(tokenFactory);
        
        MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        final MslUser user = new MockMslUser(1);
        USER_ID_TOKEN = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1L, user);
    }
    
    @AfterClass
    public static void teardown() {
        USER_ID_TOKEN = null;
        MASTER_TOKEN = null;
        
        tokenFactory = null;
        factory = null;
        authutils = null;
        encoder = null;
        ctx = null;
    }
    
    @After
    public void reset() {
        authutils.reset();
        tokenFactory.reset();
    }
    
    @Test
    public void createData() throws MslEncodingException, MslUserAuthException, MslCryptoException, MslEncoderException {
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslObject userAuthMo = data.getAuthData(encoder, ENCODER_FORMAT);
        
        final UserAuthenticationData authdata = factory.createData(ctx, null, userAuthMo);
        assertNotNull(authdata);
        assertTrue(authdata instanceof UserIdTokenAuthenticationData);
        assertEquals(data, authdata);
    }
    
    @Test
    public void encodeException() throws MslEncodingException, MslUserAuthException, MslCryptoException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslObject userAuthMo = data.getAuthData(encoder, ENCODER_FORMAT);
        userAuthMo.remove(KEY_MASTER_TOKEN);
        factory.createData(ctx, null, userAuthMo);
    }
    
    @Test
    public void authenticate() throws MslUserAuthException, MslUserIdTokenException {
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslUser user = factory.authenticate(ctx, MASTER_TOKEN.getIdentity(), data, null);
        assertNotNull(user);
        assertEquals(USER_ID_TOKEN.getUser(), user);
    }
    
    @Test
    public void authenticateUserIdToken() throws MslEncodingException, MslCryptoException, MslUserAuthException, MslUserIdTokenException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, MASTER_TOKEN.getSequenceNumber() + 1, MASTER_TOKEN.getSerialNumber() + 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, USER_ID_TOKEN.getSerialNumber() + 1, USER_ID_TOKEN.getUser());
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslUser u = factory.authenticate(ctx, MASTER_TOKEN.getIdentity(), data, userIdToken);
        assertEquals(USER_ID_TOKEN.getUser(), u);
    }
    
    @Test
    public void authenticateMismatchedUserIdToken() throws MslEncodingException, MslCryptoException, MslUserAuthException, MslUserIdTokenException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH);
        
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MslUser user = new MockMslUser(2);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, user);
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        factory.authenticate(ctx, MASTER_TOKEN.getIdentity(), data, userIdToken);
    }
    
    @Test
    public void untrustedMasterToken() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_MASTERTOKEN_NOT_DECRYPTED);
        
        final MasterToken untrustedMasterToken = MslTestUtils.getUntrustedMasterToken(ctx);
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(untrustedMasterToken, USER_ID_TOKEN);
        factory.authenticate(ctx, MASTER_TOKEN.getIdentity(), data, null);
    }
    
    @Test
    public void mismatchedMasterTokenIdentity() throws MslEncodingException, MslCryptoException, MslUserAuthException, MslUserIdTokenException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_ENTITY_MISMATCH);
        
        final MslContext mismatchedCtx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        final MasterToken mismatchedMasterToken = MslTestUtils.getMasterToken(mismatchedCtx, 1, 1);
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(mismatchedMasterToken, USER_ID_TOKEN);
        factory.authenticate(ctx, MASTER_TOKEN.getIdentity(), data, null);
    }
    
    @Test
    public void untrustedUserIdToken() throws MslEncodingException, MslCryptoException, MslEncoderException, MslException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_USERIDTOKEN_NOT_DECRYPTED);
        
        final UserIdToken untrustedUserIdToken = MslTestUtils.getUntrustedUserIdToken(ctx, MASTER_TOKEN, USER_ID_TOKEN.getSerialNumber(), USER_ID_TOKEN.getUser());
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, untrustedUserIdToken);
        factory.authenticate(ctx, MASTER_TOKEN.getIdentity(), data, null);
    }
    
    @Test
    public void userNotPermitted() throws MslUserAuthException, MslUserIdTokenException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA);
        
        authutils.disallowScheme(MASTER_TOKEN.getIdentity(), USER_ID_TOKEN.getUser(), UserAuthenticationScheme.USER_ID_TOKEN);
        
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        factory.authenticate(ctx, MASTER_TOKEN.getIdentity(), data, null);
    }

    @Test
    public void tokenRevoked() throws MslUserIdTokenException, MslUserAuthException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_REVOKED);

        tokenFactory.setRevokedUserIdToken(USER_ID_TOKEN);

        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        factory.authenticate(ctx, MASTER_TOKEN.getIdentity(), data, null);
    }
}
