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

package mslcli.client.util;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;

/**
 * <p>
 *    Client-side authentication utilities.
 *    Restrict server entity authentication to RSA keys.
 *    Restrict client entity authentication to pre-shared keys.
 *    Restrict client user authentication to email-password.
 *    Restrict client entity key exchange to asymmetric wrapped, symmetric wrapped, DH, JWE Ladder, and JWK Ladder.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ClientAuthenticationUtils implements AuthenticationUtils {

   // should be configurable

    private final Set<EntityAuthenticationScheme> allowedServerEntityAuthenticationSchemes = new HashSet<EntityAuthenticationScheme>();
    private final Set<EntityAuthenticationScheme> allowedClientEntityAuthenticationSchemes = new HashSet<EntityAuthenticationScheme>();

    private final Set<UserAuthenticationScheme>   allowedServerUserAuthenticationSchemes   = new HashSet<UserAuthenticationScheme>();
    private final Set<UserAuthenticationScheme>   allowedClientUserAuthenticationSchemes   = new HashSet<UserAuthenticationScheme>();

    private final Set<KeyExchangeScheme>          allowedServerKeyExchangeSchemes          = new HashSet<KeyExchangeScheme>();
    private final Set<KeyExchangeScheme>          allowedClientKeyExchangeSchemes          = new HashSet<KeyExchangeScheme>();

    /**
     * <p>Create a new authentication utils instance for the specified client identity.</p>
     * 
     * @param clientId local client entity identity.
     */
    public ClientAuthenticationUtils(final String clientId) {
        this.clientId = clientId;

        // set allowed entity authentication schemes
        Collections.addAll(this.allowedClientEntityAuthenticationSchemes, EntityAuthenticationScheme.PSK);
        Collections.addAll(this.allowedServerEntityAuthenticationSchemes, EntityAuthenticationScheme.RSA);

        // set allowed user authentication schemes
        Collections.addAll(this.allowedClientUserAuthenticationSchemes  , UserAuthenticationScheme.EMAIL_PASSWORD);
        // allowedServerUserAuthenticationSchemes remains empty

        // set allowed key exchange schemes
        Collections.addAll(this.allowedClientKeyExchangeSchemes, KeyExchangeScheme.ASYMMETRIC_WRAPPED
                                                               , KeyExchangeScheme.SYMMETRIC_WRAPPED
                                                               , KeyExchangeScheme.DIFFIE_HELLMAN
                                                               , KeyExchangeScheme.JWE_LADDER
                                                               , KeyExchangeScheme.JWK_LADDER
                          );
        // allowedServerKeyExchangeSchemes remains empty
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isEntityRevoked(java.lang.String)
     *
     * typical client entity probably won't be able to check its revocation status
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
        if (clientId.equals(identity)) {
            return allowedClientEntityAuthenticationSchemes.contains(scheme);
        } else {
            return allowedServerEntityAuthenticationSchemes.contains(scheme);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final UserAuthenticationScheme scheme) {
       if (clientId.equals(identity)) {
            return allowedClientUserAuthenticationSchemes.contains(scheme);
       } else {
            return allowedServerUserAuthenticationSchemes.contains(scheme);
       }
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.tokens.MslUser, com.netflix.msl.userauth.UserAuthenticationScheme)
     *
     * In this specific implementation, allowed user authentication schemes depend on entity identity, not a specific user of that entity,
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
        if (clientId.equals(identity)) {
            return allowedClientKeyExchangeSchemes.contains(scheme);
        } else {
            return allowedServerKeyExchangeSchemes.contains(scheme);
        }
    }
    
    /** Local client entity identity. */
    private final String clientId;
}
