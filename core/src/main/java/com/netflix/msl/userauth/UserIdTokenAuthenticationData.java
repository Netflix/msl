/**
 * Copyright (c) 2014 Netflix, Inc.  All rights reserved.
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

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.json.JSONException;
import org.json.JSONObject;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslException;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslUserAuthException;
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
@EqualsAndHashCode(callSuper = true)
@Getter
public class UserIdTokenAuthenticationData extends UserAuthenticationData {
    /** JSON master token key. */
    private static final String KEY_MASTER_TOKEN = "mastertoken";
    /** JSON user ID token key. */
    private static final String KEY_USER_ID_TOKEN = "useridtoken";

    /** Master token. */
    private final MasterToken masterToken;

    /** User ID token. */
    private final UserIdToken userIdToken;

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
     * provided JSON representation.
     * 
     * @param ctx MSl context.
     * @param userIdTokenAuthJO the JSON object.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslUserAuthException if the token data is invalid or the user ID
     *         token is not bound to the master token.
     */
    public UserIdTokenAuthenticationData(final MslContext ctx, final JSONObject userIdTokenAuthJO) throws MslEncodingException, MslUserAuthException {
        super(UserAuthenticationScheme.USER_ID_TOKEN);
        
        // Convert any MslExceptions into MslUserAuthException because we don't
        // want to trigger entity or user re-authentication incorrectly.
        try {
            masterToken = new MasterToken(ctx, userIdTokenAuthJO.getJSONObject(KEY_MASTER_TOKEN));
        } catch (final MslException e) {
            throw new MslUserAuthException(MslError.USERAUTH_MASTERTOKEN_INVALID, "user ID token authdata " + userIdTokenAuthJO.toString(), e);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "user ID token authdata " + userIdTokenAuthJO.toString(), e);
        }
        try {
            userIdToken = new UserIdToken(ctx, userIdTokenAuthJO.getJSONObject(KEY_USER_ID_TOKEN), masterToken);
        } catch (final MslException e) {
            throw new MslUserAuthException(MslError.USERAUTH_USERIDTOKEN_INVALID, "user ID token authdata " + userIdTokenAuthJO.toString(), e);
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "user ID token authdata " + userIdTokenAuthJO.toString(), e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.userauth.UserAuthenticationData#getAuthData()
     */
    @Override
    public JSONObject getAuthData() throws MslEncodingException {
        try {
            final JSONObject jsonObj = new JSONObject();
            jsonObj.put(KEY_MASTER_TOKEN, new JSONObject(masterToken.toJSONString()));
            jsonObj.put(KEY_USER_ID_TOKEN, new JSONObject(userIdToken.toJSONString()));
            return jsonObj;
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_ENCODE_ERROR, "user ID token authdata", e);
        }
    }

}
