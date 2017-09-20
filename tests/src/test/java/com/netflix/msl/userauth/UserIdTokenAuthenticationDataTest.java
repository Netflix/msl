/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslEncoderUtils;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.test.ExpectedMslException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MockMslUser;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * User ID token user authentication data unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UserIdTokenAuthenticationDataTest {
	/** MSL encoder format. */
	private static final MslEncoderFormat ENCODER_FORMAT = MslEncoderFormat.JSON;

    /** Key user authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** Key user authentication data. */
    private static final String KEY_AUTHDATA = "authdata";
    /** Key master token. */
    private static final String KEY_MASTER_TOKEN = "mastertoken";
    /** Key user ID token. */
    private static final String KEY_USER_ID_TOKEN = "useridtoken";
    
    @Rule
    public ExpectedMslException thrown = ExpectedMslException.none();
    
    /** Master token. */
    private static MasterToken MASTER_TOKEN;
    /** User ID token. */
    private static UserIdToken USER_ID_TOKEN;
    
    /** MSL context. */
    private static MslContext ctx;
    /** MSL encoder factory. */
    private static MslEncoderFactory encoder;
    
    @BeforeClass
    public static void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.X509, false);
        encoder = ctx.getMslEncoderFactory();
        MASTER_TOKEN = MslTestUtils.getMasterToken(ctx, 1L, 1L);
        final MslUser user = new MockMslUser(1);
        USER_ID_TOKEN = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, 1L, user);
    }
    
    @AfterClass
    public static void teardown() {
        USER_ID_TOKEN = null;
        MASTER_TOKEN = null;
        encoder = null;
        ctx = null;
    }
    
    @Test
    public void ctors() throws MslEncodingException, MslUserAuthException, MslEncoderException {
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        assertEquals(UserAuthenticationScheme.USER_ID_TOKEN, data.getScheme());
        assertEquals(MASTER_TOKEN, data.getMasterToken());
        assertEquals(USER_ID_TOKEN, data.getUserIdToken());
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(authdata);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(encode);
        
        final UserIdTokenAuthenticationData moData = new UserIdTokenAuthenticationData(ctx, authdata);
        assertEquals(data.getScheme(), moData.getScheme());
        assertEquals(data.getMasterToken(), moData.getMasterToken());
        assertEquals(data.getUserIdToken(), moData.getUserIdToken());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(moEncode, encode);
    }
    
    @Test
    public void mslObject() throws MslEncoderException {
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslObject mo = MslTestUtils.toMslObject(encoder, data);
        assertEquals(UserAuthenticationScheme.USER_ID_TOKEN.name(), mo.getString(KEY_SCHEME));
        final MslObject authdata = mo.getMslObject(KEY_AUTHDATA, encoder);
        final MslObject masterTokenJo = authdata.getMslObject(KEY_MASTER_TOKEN, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, MASTER_TOKEN), masterTokenJo));
        final MslObject userIdTokenJo = authdata.getMslObject(KEY_USER_ID_TOKEN, encoder);
        assertTrue(MslEncoderUtils.equalObjects(MslTestUtils.toMslObject(encoder, USER_ID_TOKEN), userIdTokenJo));
    }
    
    @Test
    public void create() throws MslUserAuthException, MslEncodingException, MslCryptoException, MslEncoderException {
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final byte[] encode = data.toMslEncoding(encoder, ENCODER_FORMAT);
        final MslObject mo = encoder.parseObject(encode);
        final UserAuthenticationData userdata = UserAuthenticationData.create(ctx, null, mo);
        assertNotNull(userdata);
        assertTrue(userdata instanceof UserIdTokenAuthenticationData);
        
        final UserIdTokenAuthenticationData moData = (UserIdTokenAuthenticationData)userdata;
        assertEquals(data.getScheme(), moData.getScheme());
        assertEquals(data.getMasterToken(), moData.getMasterToken());
        assertEquals(data.getUserIdToken(), moData.getUserIdToken());
        final MslObject moAuthdata = moData.getAuthData(encoder, ENCODER_FORMAT);
        assertNotNull(moAuthdata);
        final byte[] moEncode = moData.toMslEncoding(encoder, ENCODER_FORMAT);
        assertNotNull(moEncode);
        assertArrayEquals(moEncode, encode);
    }
    
    @Test
    public void missingMasterToken() throws MslEncodingException, MslUserAuthException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_MASTER_TOKEN);
        new UserIdTokenAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void invalidMasterToken() throws MslEncodingException, MslUserAuthException, MslEncoderException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_MASTERTOKEN_INVALID);
        
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_MASTER_TOKEN, new MslObject());
        new UserIdTokenAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void missingUserIdToken() throws MslEncodingException, MslUserAuthException, MslEncoderException {
        thrown.expect(MslEncodingException.class);
        thrown.expectMslError(MslError.MSL_PARSE_ERROR);
        
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.remove(KEY_USER_ID_TOKEN);
        new UserIdTokenAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void invalidUserIdToken() throws MslEncodingException, MslUserAuthException, MslEncoderException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_USERIDTOKEN_INVALID);
        
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_USER_ID_TOKEN, new MslObject());
        new UserIdTokenAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void mismatchedTokens() throws MslEncodingException, MslCryptoException, MslUserAuthException, MslEncoderException {
        thrown.expect(MslUserAuthException.class);
        thrown.expectMslError(MslError.USERAUTH_USERIDTOKEN_INVALID);
        
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, MASTER_TOKEN.getSequenceNumber(), MASTER_TOKEN.getSerialNumber() + 1);
        
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final MslObject authdata = data.getAuthData(encoder, ENCODER_FORMAT);
        authdata.put(KEY_MASTER_TOKEN, MslTestUtils.toMslObject(encoder, masterToken));
        new UserIdTokenAuthenticationData(ctx, authdata);
    }
    
    @Test
    public void equalsMasterToken() throws MslEncodingException, MslCryptoException, MslUserAuthException, MslEncoderException {
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, MASTER_TOKEN.getSequenceNumber() + 1, MASTER_TOKEN.getSerialNumber());
        
        final UserIdTokenAuthenticationData dataA = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final UserIdTokenAuthenticationData dataB = new UserIdTokenAuthenticationData(masterToken, USER_ID_TOKEN);
        final UserIdTokenAuthenticationData dataA2 = new UserIdTokenAuthenticationData(ctx, dataA.getAuthData(encoder, ENCODER_FORMAT));
        
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
    public void equalsUserIdToken() throws MslEncodingException, MslCryptoException, MslUserAuthException, MslEncoderException {
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, MASTER_TOKEN, USER_ID_TOKEN.getSerialNumber() + 1, USER_ID_TOKEN.getUser());
        
        final UserIdTokenAuthenticationData dataA = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        final UserIdTokenAuthenticationData dataB = new UserIdTokenAuthenticationData(MASTER_TOKEN, userIdToken);
        final UserIdTokenAuthenticationData dataA2 = new UserIdTokenAuthenticationData(ctx, dataA.getAuthData(encoder, ENCODER_FORMAT));
        
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
    public void equalsObject() {
        final UserIdTokenAuthenticationData data = new UserIdTokenAuthenticationData(MASTER_TOKEN, USER_ID_TOKEN);
        assertFalse(data.equals(null));
        assertFalse(data.equals(KEY_MASTER_TOKEN));
        assertTrue(data.hashCode() != KEY_MASTER_TOKEN.hashCode());
    }
}
