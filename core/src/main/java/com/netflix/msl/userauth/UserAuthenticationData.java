/**
 * Copyright 2015 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import org.json.JSONString;
import org.json.JSONStringer;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslError;
import com.netflix.msl.MslInternalException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.util.MslContext;


/**
 * <p>The user authentication data provides proof of user identity.</p>
 * 
 * <p>Specific user authentication mechanisms should define their own user
 * authentication data types.</p>
 * 
 * <p>User authentication data is represented as
 * {@code
 * userauthdata = {
 *   "#mandatory" : [ "scheme"., "authdata" ],
 *   "scheme" : "string",
 *   "authdata" : object
 * }} where
 * <ul>
 * <li>{@code scheme} is the user authentication scheme</li>
 * <li>{@code authdata} is the scheme-specific authentication data</li>
 * </ul></p>
 */
@EqualsAndHashCode
@Getter
public abstract class UserAuthenticationData implements JSONString {
    /** JSON key user authentication scheme. */
    private static final String KEY_SCHEME = "scheme";
    /** JSON key user authentication data. */
    private static final String KEY_AUTHDATA = "authdata";

    /** User authentication scheme. */
    private final UserAuthenticationScheme scheme;

    /**
     * Create a new user authentication data object with the specified user
     * authentication scheme.
     * 
     * @param scheme the user authentication scheme.
     */
    protected UserAuthenticationData(final UserAuthenticationScheme scheme) {
        this.scheme = scheme;
    }

    /**
     * <p>Construct a new user authentication data instance of the correct type
     * from the provided JSON object.</p>
     * 
     * <p>A master token may be required for certain user authentication
     * schemes.</p>
     * 
     * @param ctx MSL context.
     * @param masterToken the master token associated with the user
     *        authentication data. May be {@code null}.
     * @param userAuthJO the JSON object.
     * @return the user authentication data concrete instance.
     * @throws MslEncodingException if there is an error parsing the JSON.
     * @throws MslUserAuthException if there is an error instantiating the user
     *         authentication data.
     * @throws MslCryptoException if there is an error with the entity
     *         authentication data cryptography.
     */
    public static UserAuthenticationData create(final MslContext ctx, final MasterToken masterToken, final JSONObject userAuthJO) throws MslUserAuthException, MslEncodingException, MslCryptoException {
        try {
            // Pull the scheme.
            final String schemeName = userAuthJO.getString(KEY_SCHEME);
            final UserAuthenticationScheme scheme = ctx.getUserAuthenticationScheme(schemeName);
            if (scheme == null)
                throw new MslUserAuthException(MslError.UNIDENTIFIED_USERAUTH_SCHEME, schemeName);
            
            // Construct an instance of the concrete subclass.
            final UserAuthenticationFactory factory = ctx.getUserAuthenticationFactory(scheme);
            if (factory == null)
                throw new MslUserAuthException(MslError.USERAUTH_FACTORY_NOT_FOUND, scheme.name());
            return factory.createData(ctx, masterToken, userAuthJO.getJSONObject(KEY_AUTHDATA));
        } catch (final JSONException e) {
            throw new MslEncodingException(MslError.JSON_PARSE_ERROR, "userauthdata " + userAuthJO.toString(), e);
        }
    }

    /**
     * Returns the scheme-specific user authentication data. This method is
     * expected to succeed unless there is an internal error.
     * 
     * @return the authentication data JSON representation.
     * @throws MslEncodingException if there was an error constructing the
     *         JSON representation.
     */
    public abstract JSONObject getAuthData() throws MslEncodingException;
    
    /* (non-Javadoc)
     * @see org.json.JSONString#toJSONString()
     */
    @Override
    public final String toJSONString() {
        try {
            return new JSONStringer()
                .object()
                    .key(KEY_SCHEME).value(scheme.name())
                    .key(KEY_AUTHDATA).value(getAuthData())
                .endObject()
                .toString();
        } catch (final JSONException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        } catch (final MslEncodingException e) {
            throw new MslInternalException("Error encoding " + this.getClass().getName() + " JSON.", e);
        }
    }
}