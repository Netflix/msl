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

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationScheme;

/**
 * Test authentication utilities.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockAuthenticationUtils implements AuthenticationUtils {
    /**
     * Reset the entity revocation state.
     */
    public void reset() {
        revokedEntityIdentities.clear();
        revokedEntityAuthSchemes.clear();
        revokedUserAuthSchemes.clear();
        revokedEntityUserAuthSchemes.clear();
        revokedKeyxSchemes.clear();
    }
    
    /**
     * @param identity the entity identity to revoke.
     */
    public void revokeEntity(final String identity) {
        revokedEntityIdentities.add(identity);
    }
    
    /**
     * @param identity the entity to accept.
     */
    public void accept(final String identity) {
        revokedEntityIdentities.remove(identity);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.entityauth.EntityAuthUtils#isRevoked(java.lang.String)
     */
    @Override
    public boolean isEntityRevoked(final String identity) {
        return revokedEntityIdentities.contains(identity);
    }
    
    /**
     * @param identity the entity identity.
     * @param scheme the scheme to permit.
     */
    public void permitScheme(final String identity, final EntityAuthenticationScheme scheme) {
        final Set<EntityAuthenticationScheme> revokedSchemes = revokedEntityAuthSchemes.get(identity);
        if (revokedSchemes == null) return;
        revokedSchemes.remove(scheme);
    }

    /**
     * @param identity the entity identity.
     * @param scheme the scheme to disallow.
     */
    public void disallowScheme(final String identity, final EntityAuthenticationScheme scheme) {
        if (!revokedEntityAuthSchemes.containsKey(identity))
            revokedEntityAuthSchemes.put(identity, new HashSet<EntityAuthenticationScheme>());
        final Set<EntityAuthenticationScheme> revokedSchemes = revokedEntityAuthSchemes.get(identity);
        revokedSchemes.add(scheme);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final EntityAuthenticationScheme scheme) {
        return (!revokedEntityAuthSchemes.containsKey(identity) ||
                !revokedEntityAuthSchemes.get(identity).contains(scheme));
    }

    /**
     * @param identity the entity identity.
     * @param scheme the scheme to permit.
     */
    public void permitScheme(final String identity, final UserAuthenticationScheme scheme) {
        final Set<UserAuthenticationScheme> revokedSchemes = revokedUserAuthSchemes.get(identity);
        if (revokedSchemes == null) return;
        revokedSchemes.remove(scheme);
    }

    /**
     * @param identity the entity identity.
     * @param scheme the scheme to disallow.
     */
    public void disallowScheme(final String identity, final UserAuthenticationScheme scheme) {
        if (!revokedUserAuthSchemes.containsKey(identity))
            revokedUserAuthSchemes.put(identity, new HashSet<UserAuthenticationScheme>());
        final Set<UserAuthenticationScheme> revokedSchemes = revokedUserAuthSchemes.get(identity);
        revokedSchemes.add(scheme);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final UserAuthenticationScheme scheme) {
        return (!revokedUserAuthSchemes.containsKey(identity) ||
            !revokedUserAuthSchemes.get(identity).contains(scheme));
    }
    
    /**
     * @param identity the entity identity.
     * @param user the MSL user.
     * @param scheme the scheme to permit.
     */
    public void permitScheme(final String identity, final MslUser user, final UserAuthenticationScheme scheme) {
        final Map<MslUser,Set<UserAuthenticationScheme>> entityUsers = revokedEntityUserAuthSchemes.get(identity);
        if (entityUsers == null) return;
        final Set<UserAuthenticationScheme> revokedSchemes = entityUsers.get(user);
        if (revokedSchemes == null) return;
        revokedSchemes.remove(scheme);
    }
    
    /**
     * @param identity the entity identity.
     * @param user the MSL user.
     * @param scheme the scheme to disallow.
     */
    public void disallowScheme(final String identity, final MslUser user, final UserAuthenticationScheme scheme) {
        Map<MslUser,Set<UserAuthenticationScheme>> entityUsers = revokedEntityUserAuthSchemes.get(identity);
        if (entityUsers == null) {
            entityUsers = new HashMap<MslUser,Set<UserAuthenticationScheme>>();
            revokedEntityUserAuthSchemes.put(identity, entityUsers);
        }
        Set<UserAuthenticationScheme> revokedSchemes = entityUsers.get(user);
        if (revokedSchemes == null) {
            revokedSchemes = new HashSet<UserAuthenticationScheme>();
            entityUsers.put(user, revokedSchemes);
        }
        revokedSchemes.add(scheme);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.tokens.MslUser, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final MslUser user, final UserAuthenticationScheme scheme) {
        final Map<MslUser,Set<UserAuthenticationScheme>> entityUsers = revokedEntityUserAuthSchemes.get(identity);
        if (entityUsers == null) return true;
        final Set<UserAuthenticationScheme> revokedSchemes = entityUsers.get(user);
        if (revokedSchemes == null) return true;
        return !revokedSchemes.contains(scheme);
    }

    /**
     * @param identity the entity identity.
     * @param scheme the scheme to permit.
     */
    public void permitScheme(final String identity, final KeyExchangeScheme scheme) {
        final Set<KeyExchangeScheme> revokedSchemes = revokedKeyxSchemes.get(identity);
        if (revokedSchemes == null) return;
        revokedSchemes.remove(scheme);
    }
    
    /**
     * @param identity the entity identity.
     * @param scheme the scheme to disallow.
     */
    public void disallowScheme(final String identity, final KeyExchangeScheme scheme) {
        if (!revokedKeyxSchemes.containsKey(identity))
            revokedKeyxSchemes.put(identity, new HashSet<KeyExchangeScheme>());
        final Set<KeyExchangeScheme> revokedSchemes = revokedKeyxSchemes.get(identity);
        revokedSchemes.add(scheme);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.keyx.KeyExchangeScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final KeyExchangeScheme scheme) {
        return (!revokedKeyxSchemes.containsKey(identity) ||
            !revokedKeyxSchemes.get(identity).contains(scheme));
    }

    /** Revoked entity identities. */
    private final Set<String> revokedEntityIdentities = new HashSet<String>();
    /** Revoked entity authentication schemes. */
    private final Map<String,Set<EntityAuthenticationScheme>> revokedEntityAuthSchemes = new HashMap<String,Set<EntityAuthenticationScheme>>();
    /** Revoked user authentication schemes. */
    private final Map<String,Set<UserAuthenticationScheme>> revokedUserAuthSchemes = new HashMap<String,Set<UserAuthenticationScheme>>();
    /** Revoked entity-user authentication schemes. */
    private final Map<String,Map<MslUser,Set<UserAuthenticationScheme>>> revokedEntityUserAuthSchemes = new HashMap<String,Map<MslUser,Set<UserAuthenticationScheme>>>();
    /** Revoked key exchange schemes. */
    private final Map<String,Set<KeyExchangeScheme>> revokedKeyxSchemes = new HashMap<String,Set<KeyExchangeScheme>>();
}
