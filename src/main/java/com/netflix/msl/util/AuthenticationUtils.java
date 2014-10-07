/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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

import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * Authentication utility functions.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public interface AuthenticationUtils {
    /**
     * Returns true if the entity identity has been revoked.
     * 
     * @param identity the entity identity.
     * @return true if the entity identity has been revoked.
     */
    public boolean isEntityRevoked(final String identity);
    
    /**
     * Returns true if the identified entity is permitted to use the specified
     * entity authentication scheme.
     * 
     * @param identity the entity identity.
     * @param scheme the entity authentication scheme.
     * @return true if the entity is permitted to use the scheme. 
     */
    public boolean isSchemePermitted(final String identity, final EntityAuthenticationScheme scheme);
    
    /**
     * Returns true if the identified entity is permitted to use the specified
     * user authentication scheme.
     * 
     * @param identity the entity identity.
     * @param scheme the user authentication scheme.
     * @return true if the entity is permitted to use the scheme.
     */
    public boolean isSchemePermitted(final String identity, final UserAuthenticationScheme scheme);
    
    /**
     * Returns true if the identified entity and user combination is permitted
     * to use the specified user authentication scheme.
     * 
     * @param identity the entity identity.
     * @param user the user.
     * @param scheme the user authentication scheme.
     * @return true if the entity and user are permitted to use the scheme.
     */
    public boolean isSchemePermitted(final String identity, final MslUser user, final UserAuthenticationScheme scheme);
    
    /**
     * Returns true if the identified entity is permitted to use the specified
     * key exchange scheme.
     * 
     * @param identity the entity identity.
     * @param scheme the key exchange scheme.
     * @return true if the entity is permitted to use the scheme.
     */
    public boolean isSchemePermitted(final String identity, final KeyExchangeScheme scheme);
}
