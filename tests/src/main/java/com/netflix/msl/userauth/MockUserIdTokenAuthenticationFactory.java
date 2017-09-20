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

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;

/**
 * Test user ID token authentication factory.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockUserIdTokenAuthenticationFactory extends UserAuthenticationFactory {
    /**
     * Create a new test user ID token authentication factory. By default no
     * tokens are accepted.
     */
    public MockUserIdTokenAuthenticationFactory() {
        super(UserAuthenticationScheme.USER_ID_TOKEN);
    }

    /**
     * <p>Set the master token and user ID token pair to accept. The user ID
     * token must be bound to the master token.</p>
     * 
     * @param masterToken the master token to accept.
     * @param userIdToken the user ID token to accept.
     */
    public void setTokens(final MasterToken masterToken, final UserIdToken userIdToken) {
        if (!userIdToken.isBoundTo(masterToken))
            throw new MslInternalException("The user ID token must be bound to the master token.");
        this.masterToken = masterToken;
        this.userIdToken = userIdToken;
    }
    
    /**
     * @return the accepted master token.
     */
    public MasterToken getMasterToken() {
        return masterToken;
    }
    
    /**
     * @return the accepted user ID token.
     */
    public UserIdToken getUserIdToken() {
        return userIdToken;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#createData(com.netflix.msl.util.MslContext, com.netflix.msl.tokens.MasterToken, com.netflix.msl.io.MslObject)
     */
    @Override
    public UserAuthenticationData createData(final MslContext ctx, final MasterToken masterToken, final MslObject userAuthMo) throws MslEncodingException, MslUserAuthException {
        return new UserIdTokenAuthenticationData(ctx, userAuthMo);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationFactory#authenticate(com.netflix.msl.util.MslContext, java.lang.String, com.netflix.msl.userauth.UserAuthenticationData, com.netflix.msl.tokens.UserIdToken)
     */
    @Override
    public MslUser authenticate(final MslContext ctx, final String identity, final UserAuthenticationData data, final UserIdToken userIdToken) throws MslUserAuthException {
        // Make sure we have the right kind of user authentication data.
        if (!(data instanceof UserIdTokenAuthenticationData))
            throw new MslInternalException("Incorrect authentication data type " + data.getClass().getName() + ".");
        final UserIdTokenAuthenticationData uitad = (UserIdTokenAuthenticationData)data;
        
        // Extract and check master token.
        final MasterToken uitadMasterToken = uitad.getMasterToken();
        final String uitadIdentity = uitadMasterToken.getIdentity();
        if (uitadIdentity == null)
            throw new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_NOT_DECRYPTED).setUserAuthenticationData(uitad);
        if (!identity.equals(uitadIdentity))
            throw new MslUserAuthException(MslError.USERAUTH_ENTITY_MISMATCH, "entity identity " + identity + "; uad identity " + uitadIdentity).setUserAuthenticationData(uitad);
        
        // Authenticate the user.
        final UserIdToken uitadUserIdToken = uitad.getUserIdToken();
        final MslUser user = uitadUserIdToken.getUser();
        if (user == null)
            throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_NOT_DECRYPTED).setUserAuthenticationData(uitad);
        
        // Verify the user.
        if (!uitadMasterToken.equals(masterToken) ||
            !uitadUserIdToken.equals(userIdToken))
        {
            throw new MslUserAuthException(MslError.USERAUTH_ENTITYUSER_INCORRECT_DATA, "Authentication scheme " + this.getScheme() + " not permitted for entity " + identity + ".").setUserAuthenticationData(data);
        }
        
        // If a user ID token was provided validate the user identities.
        if (userIdToken != null) {
            final MslUser uitUser = userIdToken.getUser();
            if (!user.equals(uitUser))
                throw new MslUserAuthException(MslError.USERIDTOKEN_USERAUTH_DATA_MISMATCH, "uad user " + user + "; uit user " + uitUser).setUserAuthenticationData(uitad);
        }
        
        // Return the user.
        return user;
    }
    
    /** Master token. */
    private MasterToken masterToken = null;
    /** User ID token. */
    private UserIdToken userIdToken = null;
}
