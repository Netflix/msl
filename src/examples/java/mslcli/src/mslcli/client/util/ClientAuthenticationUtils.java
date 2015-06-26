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

import mslcli.common.util.AppContext;

/**
 * <p>
 *    Utility telling which entity authentication, user authentication, and key exchange
 *    mechanisms are allowed/supported for a given entity
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ClientAuthenticationUtils implements AuthenticationUtils {

   // should be configurable

    private final Set<EntityAuthenticationScheme> allowedClientEntityAuthenticationSchemes;
    private final Set<UserAuthenticationScheme>   allowedClientUserAuthenticationSchemes;
    private final Set<KeyExchangeScheme>          allowedClientKeyExchangeSchemes;

    /**
     * <p>Create a new authentication utils instance for the specified client identity.</p>
     * 
     * @param clientId local client entity identity.
     */
    public ClientAuthenticationUtils(final String clientId, final AppContext appCtx) {
        this.clientId = clientId;
        this.appCtx = appCtx;

        // set allowed entity authentication schemes
        this.allowedClientEntityAuthenticationSchemes = appCtx.getAllowedEntityAuthenticationSchemes(clientId);;

        // set allowed user authentication schemes
        this.allowedClientUserAuthenticationSchemes = appCtx.getAllowedUserAuthenticationSchemes(clientId);

        // set allowed key exchange schemes
        this.allowedClientKeyExchangeSchemes = appCtx.getAllowedKeyExchangeSchemes(clientId);
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
            return appCtx.getAllowedEntityAuthenticationSchemes(identity).contains(scheme);
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
            appCtx.warning(String.format("client %s: user authentication schema support inquiry for entity %s", clientId, identity));
            return false;
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
            appCtx.warning(String.format("client %s: key exchange schema support inquiry for entity %s", clientId, identity));
            return false;
        }
    }
    
    /** Local client entity identity. */
    private final String clientId;

    /** Local client entity identity. */
    private final AppContext appCtx;
}
