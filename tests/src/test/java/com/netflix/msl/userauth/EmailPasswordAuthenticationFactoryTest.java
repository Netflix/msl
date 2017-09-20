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
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MockAuthenticationUtils;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * Email/password user authentication factory unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class EmailPasswordAuthenticationFactoryTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key email. */
    private static final String KEY_EMAIL = "email";
    
    /** Empty string. */
    private static final String EMPTY_STRING = "";

    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
        encoder = ctx.getMslEncoderFactory();
        final MockEmailPasswordStore store = new MockEmailPasswordStore();
        store.addUser(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD, MockEmailPasswordAuthenticationFactory.USER);
        authutils = new MockAuthenticationUtils();
        factory = new EmailPasswordAuthenticationFactory(store, authutils);
        ctx.addUserAuthenticationFactory(factory);
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
    public void createData() throws MslEncodingException, MslUserAuthException, MslEncoderException, MslCryptoException {
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final MslObject userAuthMo = data.getAuthData(encoder, ENCODER_FORMAT);
        
        final UserAuthenticationData authdata = factory.createData(ctx, null, userAuthMo);
        assertNotNull(authdata);
        assertTrue(authdata instanceof EmailPasswordAuthenticationData);
        
        final MslObject dataMo = MslTestUtils.toMslObject(encoder, data);
        final MslObject authdataMo = MslTestUtils.toMslObject(encoder, authdata);
        assertTrue(MslEncoderUtils.equalObjects(dataMo, authdataMo));
    }
    
    @Test
    public void encodeException() throws MslEncodingException, MslUserAuthException, MslCryptoException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);

        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final MslObject userAuthMo = data.getAuthData(encoder, ENCODER_FORMAT);
        userAuthMo.remove(KEY_EMAIL);
        factory.createData(ctx, null, userAuthMo);
    }
    
    @Test
    public void authenticate() throws MslUserAuthException, MslUserIdTokenException {
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final MslUser user = factory.authenticate(ctx, null, data, null);
        assertNotNull(user);
        assertEquals(MockEmailPasswordAuthenticationFactory.USER, user);
    }
    
    @Test
    public void authenticateUserIdToken() throws MslEncodingException, MslCryptoException, MslUserAuthException, MslUserIdTokenException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MslUser user = MockEmailPasswordAuthenticationFactory.USER;
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, user);
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        final MslUser u = factory.authenticate(ctx, null, data, userIdToken);
        assertEquals(user, u);
    }
    
    @Test
    public void authenticateMismatchedUserIdToken() throws MslEncodingException, MslCryptoException, MslUserAuthException, MslUserIdTokenException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH);

        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final MslUser user = MockEmailPasswordAuthenticationFactory.USER_2;
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, user);
        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD);
        factory.authenticate(ctx, null, data, userIdToken);
    }
    
    @Test
    public void emailBlank() throws MslUserAuthException, MslUserIdTokenException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.EMAILPASSWORD_BLANK);

        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(EMPTY_STRING, MockEmailPasswordAuthenticationFactory.PASSWORD);
        factory.authenticate(ctx, null, data, null);
    }
    
    @Test
    public void passwordBlank() throws MslUserAuthException, MslUserIdTokenException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.EMAILPASSWORD_BLANK);

        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, EMPTY_STRING);
        factory.authenticate(ctx, null, data, null);
    }
    
    @Test
    public void badLogin() throws MslUserAuthException, MslUserIdTokenException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.EMAILPASSWORD_INCORRECT);

        final EmailPasswordAuthenticationData data = new EmailPasswordAuthenticationData(MockEmailPasswordAuthenticationFactory.EMAIL, MockEmailPasswordAuthenticationFactory.PASSWORD + "x");
        factory.authenticate(ctx, null, data, null);
    }
    
    /** MSL context. */
    private static MockMslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    /** Authentication utilities. */
    private static MockAuthenticationUtils authutils;
    /** User authentication factory. */
    private static UserAuthenticationFactory factory;
}
