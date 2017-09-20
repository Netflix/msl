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
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;

/**
 * <p>User ID token-based user authentication data.</p>
 * 
 * <p>
 * {@code {
 *   "#mandatory" : [ "mastertoken", "useridtoken" ],
 *   "mastertoken" : mastertoken,
 *   "useridtoken" : useridtoken,
 * }} where:
 * <ul>
 * <li>{@code mastertoken} is the master token</li>
 * <li>{@code useridtoken} is the user ID token</li>
 * </ul></p>
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class UserIdTokenAuthenticationData extends UserAuthenticationData {
    /** Key master token. */
    private static final String KEY_MASTER_TOKEN = "mastertoken";
    /** Key user ID token. */
    private static final String KEY_USER_ID_TOKEN = "useridtoken";
    
    /**
     * Construct a new user ID token authentication data instance from the
     * provided master token and user ID token.
     * 
     * @param masterToken the master token.
     * @param userIdToken the user ID token.
     */
    public UserIdTokenAuthenticationData(final MasterToken masterToken, final UserIdToken userIdToken) {
        super(UserAuthenticationScheme.USER_ID_TOKEN);
        if (!userIdToken.isBoundTo(masterToken))
            throw new MslInternalException("User ID token must be bound to master token.");
        this.masterToken = masterToken;
        this.userIdToken = userIdToken;
    }
    
    /**
     * Construct a new user ID token authentication data instance from the
     * provided MSL object.
     * 
     * @param ctx MSl context.
     * @param userIdTokenAuthMo the MSL object.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslUserAuthException if the token data is invalid or the user ID
     *         token is not bound to the master token.
     */
    public UserIdTokenAuthenticationData(final MslContext ctx, final MslObject userIdTokenAuthMo) throws MslEncodingException, MslUserAuthException {
        super(UserAuthenticationScheme.USER_ID_TOKEN);

        // Extract master token and user ID token representations.
        final MslEncoderFactory encoder = ctx.getMslEncoderFactory();
        final MslObject masterTokenMo, userIdTokenMo;
        try {
            masterTokenMo = userIdTokenAuthMo.getMslObject(KEY_MASTER_TOKEN, encoder);
            userIdTokenMo = userIdTokenAuthMo.getMslObject(KEY_USER_ID_TOKEN, encoder);
        } catch (final MslEncoderException e) {
            throw new MslEncodingException(MslError.MSL_PARSE_ERROR, "user ID token authdata " + userIdTokenAuthMo, e);
        }
        
        // Convert any MslExceptions into MslUserAuthException because we don't
        // want to trigger entity or user re-authentication incorrectly.
        try {
            masterToken = new MasterToken(ctx, masterTokenMo);
        } catch (final MslException e) {
            throw new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_INVALID, "user ID token authdata " + userIdTokenAuthMo, e);
        }
        try {
            userIdToken = new UserIdToken(ctx, userIdTokenMo, masterToken);
        } catch (final MslException e) {
            throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_INVALID, "user ID token authdata " + userIdTokenAuthMo, e);
        }
    }
    
    /**
     * @return the master token.
     */
    public MasterToken getMasterToken() {
        return masterToken;
    }
    
    /**
     * @return the user ID token.
     */
    public UserIdToken getUserIdToken() {
        return userIdToken;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#getAuthData(com.netflix.msl.io.MslEncoderFactory, com.netflix.msl.io.MslEncoderFormat)
     */
    @Override
    public MslObject getAuthData(final MslEncoderFactory encoder, final MslEncoderFormat format) throws MslEncoderException {
        final MslObject authdata = encoder.createObject();
        authdata.put(KEY_MASTER_TOKEN, masterToken);
        authdata.put(KEY_USER_ID_TOKEN, userIdToken);
        return encoder.parseObject(encoder.encodeObject(authdata, format));
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (obj == this) return true;
        if (!(obj instanceof UserIdTokenAuthenticationData)) return false;
        final UserIdTokenAuthenticationData that = (UserIdTokenAuthenticationData)obj;
        return super.equals(obj) && masterToken.equals(that.masterToken) && userIdToken.equals(that.userIdToken);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#hashCode()
     */
    @Override
    public int hashCode() {
        return super.hashCode() ^ masterToken.hashCode() ^ userIdToken.hashCode();
    }

    /** Master token. */
    private final MasterToken masterToken;
    /** User ID token. */
    private final UserIdToken userIdToken;
}
