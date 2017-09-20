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
package com.netflix.msl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.MockEmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.util.MockMslContext;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslTestUtils;

/**
 * MslException unit tests.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MslExceptionTest {
    /**
     * @return dummy user authentication data.
     */
    private static UserAuthenticationData getUserAuthenticationData() {
        return new EmailPasswordAuthenticationData("email", "password");
    }
    
    /** MSL context. */
    private MslContext ctx;
    
    @Before
    public void setup() throws MslEncodingException, MslCryptoException {
        ctx = new MockMslContext(EntityAuthenticationScheme.PSK, false);
    }
    
    @Test
    public void error() {
        final MslException e = new MslException(MslError.MSL_PARSE_ERROR);
        assertEquals(MslError.MSL_PARSE_ERROR, e.getError());
        assertEquals(MslError.MSL_PARSE_ERROR.getMessage(), e.getMessage());
    }
    
    @Test
    public void errorDetails() {
        final MslException e = new MslException(MslError.MSL_ENCODE_ERROR, "details");
        assertEquals(MslError.MSL_ENCODE_ERROR, e.getError());
        assertEquals(MslError.MSL_ENCODE_ERROR.getMessage() + " [details]", e.getMessage());
    }
    
    @Test
    public void errorDetailsCause() {
        final MslException e = new MslException(MslError.ENCRYPT_ERROR, "details", new RuntimeException("cause"));
        assertEquals(MslError.ENCRYPT_ERROR, e.getError());
        assertEquals(MslError.ENCRYPT_ERROR.getMessage() + " [details]", e.getMessage());
        final Throwable cause = e.getCause();
        assertTrue(cause instanceof RuntimeException);
        assertEquals("cause", cause.getMessage());
    }
    
    @Test
    public void errorCause() {
        final MslException e = new MslException(MslError.DECRYPT_ERROR, new RuntimeException("cause"));
        assertEquals(MslError.DECRYPT_ERROR, e.getError());
        assertEquals(MslError.DECRYPT_ERROR.getMessage(), e.getMessage());
        final Throwable cause = e.getCause();
        assertTrue(cause instanceof RuntimeException);
        assertEquals("cause", cause.getMessage());
    }
    
    @Test
    public void setEntityMasterToken() throws MslEncodingException, MslCryptoException {
        final MslException e = new MslException(MslError.MSL_PARSE_ERROR);
        assertNull(e.getMasterToken());
        assertNull(e.getEntityAuthenticationData());
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        e.setMasterToken(masterToken);
        e.setEntityAuthenticationData(ctx.getEntityAuthenticationData(null));
        assertEquals(masterToken, e.getMasterToken());
        assertNull(e.getEntityAuthenticationData());
    }
    
    @Test
    public void setEntityEntityAuthData() {
        final MslException e = new MslException(MslError.MSL_PARSE_ERROR);
        assertNull(e.getMasterToken());
        assertNull(e.getEntityAuthenticationData());
        final EntityAuthenticationData entityAuthData = ctx.getEntityAuthenticationData(null);
        e.setEntityAuthenticationData(entityAuthData);
        assertNull(e.getMasterToken());
        assertEquals(entityAuthData, e.getEntityAuthenticationData());
    }
    
    @Test
    public void setUserUserIdToken() throws MslEncodingException, MslCryptoException {
        final MslException e = new MslException(MslError.MSL_PARSE_ERROR);
        assertNull(e.getUserIdToken());
        assertNull(e.getUserAuthenticationData());
        final MasterToken masterToken = MslTestUtils.getMasterToken(ctx, 1, 1);
        final UserIdToken userIdToken = MslTestUtils.getUserIdToken(ctx, masterToken, 1, MockEmailPasswordAuthenticationFactory.USER);
        final UserAuthenticationData userAuthData = getUserAuthenticationData();
        e.setUserIdToken(userIdToken);
        e.setUserAuthenticationData(userAuthData);
        assertEquals(userIdToken, e.getUserIdToken());
        assertNull(e.getUserAuthenticationData());
    }
    
    @Test
    public void setUserUserAuthData() {
        final MslException e = new MslException(MslError.MSL_PARSE_ERROR);
        assertNull(e.getUserIdToken());
        assertNull(e.getUserAuthenticationData());
        final UserAuthenticationData userAuthData = getUserAuthenticationData();
        e.setUserAuthenticationData(userAuthData);
        assertNull(e.getUserIdToken());
        assertEquals(userAuthData, e.getUserAuthenticationData());
    }
    
    @Test
    public void setMessageId() {
        final MslException e = new MslException(MslError.MSL_PARSE_ERROR);
        assertNull(e.getMessageId());
        e.setMessageId(1);
        assertEquals(Long.valueOf(1), e.getMessageId());
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void negativeMessageId() {
        final MslException e = new MslException(MslError.MSL_PARSE_ERROR);
        e.setMessageId(-1);
    }

    @Test(expected = IllegalArgumentException.class)
    public void tooLargeMessageId() {
        final MslException e = new MslException(MslError.MSL_PARSE_ERROR);
        e.setMessageId(MslConstants.MAX_LONG_VALUE + 1);
    }
}