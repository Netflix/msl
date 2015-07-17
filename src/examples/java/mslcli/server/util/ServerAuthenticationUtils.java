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

import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;

/**
 * <p>
 *    Authentication utility telling which entity authentication, user authentication,
 *    and key exchange schemes are permitted/supported for a given entity.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ServerAuthenticationUtils implements AuthenticationUtils {

    /** entity authentication schemes that this server entity is allowed to use to authenticate itself */
    private final Set<EntityAuthenticationScheme> allowedServerEntityAuthenticationSchemes;

    /**
     * <p>Create a new authentication utils instance for the specified server identity.
     * </p>
     * 
     * @param appCtx application context
     * @param serverId local server entity identity.
     * @throws ConfigurationException if some configuration parameters required for initialization are missing, invalid, or inconsistent
     */
    public ServerAuthenticationUtils(final AppContext appCtx, final String serverId) throws ConfigurationException {
        if (appCtx == null) {
            throw new IllegalArgumentException("NULL app context");
        }
        if (serverId == null) {
            throw new IllegalArgumentException("NULL server ID");
        }
        this.appCtx = appCtx;
        this.serverId = serverId;
        // set allowed server entity authentication schemes
        this.allowedServerEntityAuthenticationSchemes = appCtx.getAllowedEntityAuthenticationSchemes(serverId);
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isEntityRevoked(java.lang.String)
     *
     * May query entity revocation status in real life ...
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
            try{
                return appCtx.getAllowedEntityAuthenticationSchemes(identity).contains(scheme);
            } catch (ConfigurationException e) {
                appCtx.warning(String.format("Entity %s: no entity authentication schemes configured", identity));
                return false;
            }
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final UserAuthenticationScheme scheme) {
        if (serverId.equals(identity)) {
            appCtx.warning(String.format("server %s: supported user authentication scheme inquiry for itself", serverId));
            return false; // server has no local users to authenticate
       } else {
            try{
                return appCtx.getAllowedUserAuthenticationSchemes(identity).contains(scheme);
            } catch (ConfigurationException e) {
                appCtx.warning(String.format("Entity %s: no user authentication schemes configured", identity));
                return false;
            }
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
        if (serverId.equals(identity)) {
            appCtx.warning(String.format("server %s: supported key exchange scheme inquiry for itself", serverId));
            return false; // server never initiates key exchange
        } else {
            try{
                return appCtx.getAllowedKeyExchangeSchemes(identity).contains(scheme);
            } catch (ConfigurationException e) {
                appCtx.warning(String.format("Entity %s: no key exchange schemes configured", identity));
                return false;
            }
        }
    }
    
    /** app context */
    private final AppContext appCtx;

    /** Local server entity identity. */
    private final String serverId;
}
