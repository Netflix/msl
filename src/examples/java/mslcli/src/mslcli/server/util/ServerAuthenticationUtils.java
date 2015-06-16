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

package mslcli.server.util;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;

/**
 * <p>Restrict client authentication to unauthenticated.
 *    Restrict server entity authentication to pre-shared keys.
 *    Restrict user authentication to email-password.
 *    Restrict key exchange to asymmetric wrapped key exchange.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ServerAuthenticationUtils implements AuthenticationUtils {

    // should be configurable

    private final Set<EntityAuthenticationScheme> allowedServerEntityAuthenticationSchemes = new HashSet<EntityAuthenticationScheme>();
    private final Set<EntityAuthenticationScheme> allowedClientEntityAuthenticationSchemes = new HashSet<EntityAuthenticationScheme>();

    private final Set<UserAuthenticationScheme>   allowedServerUserAuthenticationSchemes   = new HashSet<UserAuthenticationScheme>();
    private final Set<UserAuthenticationScheme>   allowedClientUserAuthenticationSchemes   = new HashSet<UserAuthenticationScheme>();

    private final Set<KeyExchangeScheme>          allowedServerKeyExchangeSchemes          = new HashSet<KeyExchangeScheme>();
    private final Set<KeyExchangeScheme>          allowedClientKeyExchangeSchemes          = new HashSet<KeyExchangeScheme>();

    /**
     * <p>Create a new authentication utils instance for the specified server
     * identity.</p>
     * 
     * @param serverId local server entity identity.
     */
    public ServerAuthenticationUtils(final String serverId) {
        this.serverId = serverId;

        Collections.addAll(this.allowedServerEntityAuthenticationSchemes, EntityAuthenticationScheme.RSA);
        Collections.addAll(this.allowedClientEntityAuthenticationSchemes, EntityAuthenticationScheme.PSK);

        Collections.addAll(this.allowedClientUserAuthenticationSchemes  , UserAuthenticationScheme.EMAIL_PASSWORD);
        // allowedServerUserAuthenticationSchemes remains empty

        Collections.addAll(this.allowedServerKeyExchangeSchemes         , KeyExchangeScheme.ASYMMETRIC_WRAPPED
                                                                        , KeyExchangeScheme.SYMMETRIC_WRAPPED
                          );
        Collections.addAll(this.allowedClientKeyExchangeSchemes         , KeyExchangeScheme.ASYMMETRIC_WRAPPED
                                                                        , KeyExchangeScheme.SYMMETRIC_WRAPPED
                                                                        , KeyExchangeScheme.DIFFIE_HELLMAN
                                                                        , KeyExchangeScheme.JWE_LADDER
                                                                        , KeyExchangeScheme.JWK_LADDER
                          );
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isEntityRevoked(java.lang.String)
     *
     * Should query entity status in real life ...
     */
    @Override
    public boolean isEntityRevoked(final String identity) {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final EntityAuthenticationScheme scheme) {
        if (serverId.equals(identity)) {
            return allowedServerEntityAuthenticationSchemes.contains(scheme);
        } else {
            return allowedClientEntityAuthenticationSchemes.contains(scheme);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final UserAuthenticationScheme scheme) {
        if (serverId.equals(identity)) {
            return allowedServerUserAuthenticationSchemes.contains(scheme);
       } else {
            return allowedClientUserAuthenticationSchemes.contains(scheme);
       }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.tokens.MslUser, com.netflix.msl.userauth.UserAuthenticationScheme)
     *
     * In this specific implementation, iallowed user authentication schemes depend on entity identity, not a specific user of that entity,
     * so the implementation is the same as in the method above.
     */
    @Override
    public boolean isSchemePermitted(final String identity, final MslUser user, final UserAuthenticationScheme scheme) {
        return isSchemePermitted(identity, scheme);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.keyx.KeyExchangeScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final KeyExchangeScheme scheme) {
        if (serverId.equals(identity)) {
            return allowedServerKeyExchangeSchemes.contains(scheme);
        } else {
            return allowedClientKeyExchangeSchemes.contains(scheme);
        }
    }
    
    /** Local server entity identity. */
    private final String serverId;
}
