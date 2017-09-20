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

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslUserAuthException;
import com.netflix.msl.MslUserIdTokenException;
import com.netflix.msl.io.MslObject;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.util.MslContext;

/**
 * A user authentication factory creates authentication data instances and
 * performs authentication for a specific user authentication scheme.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public abstract class UserAuthenticationFactory {
    /**
     * Create a new user authentication factory for the specified scheme.
     * 
     * @param scheme the user authentication scheme.
     */
    protected UserAuthenticationFactory(final UserAuthenticationScheme scheme) {
        this.scheme = scheme;
    }
    
    /**
     * @return the user authentication scheme this factory is for.
     */
    public UserAuthenticationScheme getScheme() {
        return scheme;
    }
    
    /**
     * <p>Construct a new user authentication data instance from the provided
     * MSL object.</p>
     * 
     * <p>A master token may be required for certain user authentication
     * schemes.</p>
     * 
     * @param ctx MSL context.
     * @param masterToken the entity master token. May be {@code null}.
     * @param userAuthMo the MSL object.
     * @return the user authentication data.
     * @throws MslEncodingException if there is an error parsing the data.
     * @throws MslUserAuthException if there is an error creating the user
     *         authentication data.
     * @throws MslCryptoException if there is an error with the user
     *         authentication data cryptography.
     */
    public abstract UserAuthenticationData createData(final MslContext ctx, final MasterToken masterToken, final MslObject userAuthMo) throws MslEncodingException, MslUserAuthException, MslCryptoException;

    /**
     * <p>Authenticate the user using the provided authentication data.</p>
     * 
     * <p>If a user ID token is provided then also validate the authenticated
     * user against the provided user ID token. This is typically a check to
     * ensure the user identities are equal but not always. The returned user
     * must be the user identified by the user ID token.</p>
     * 
     * @param ctx MSL context.
     * @param identity the entity identity.
     * @param data user authentication data.
     * @param userIdToken user ID token. May be {@code null}.
     * @return the MSL user.
     * @throws MslUserAuthException if there is an error authenticating the
     *         user or if the user authentication data and user ID token
     *         identities do not match.
     * @throws MslUserIdTokenException if there is a problem with the user ID
     *         token.
     */
    public abstract MslUser authenticate(final MslContext ctx, final String identity, final UserAuthenticationData data, final UserIdToken userIdToken) throws MslUserAuthException, MslUserIdTokenException;
    
    /** The factory's user authentication scheme. */
    private final UserAuthenticationScheme scheme;
}
