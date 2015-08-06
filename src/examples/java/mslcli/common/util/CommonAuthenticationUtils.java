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

package mslcli.common.util;

import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.tokens.MslUser;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;

import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.ConfigurationRuntimeException;

/**
 * <p>
 *    Utility telling which entity authentication, user authentication, and key exchange
 *    mechanisms are allowed/supported for a given entity.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class CommonAuthenticationUtils implements AuthenticationUtils {
    /**
     * <p>Create a new authentication utils instance.</p>
     * 
     * @param entityId entity identity
     * @param appCtx application context
     * @throws ConfigurationException
     */
    protected CommonAuthenticationUtils(final String entityId, final AppContext appCtx) throws ConfigurationException {
        if (entityId == null) {
            throw new IllegalArgumentException("NULL entity identity");
        }
        if (appCtx == null) {
            throw new IllegalArgumentException("NULL app context");
        }
        this.entityId = entityId;
        this.appCtx = appCtx;
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
        try {
            return appCtx.getAllowedEntityAuthenticationSchemes(identity).contains(scheme);
        } catch (ConfigurationException e) {
            throw new ConfigurationRuntimeException(e);
        }
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.AuthenticationUtils#isSchemePermitted(java.lang.String, com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public boolean isSchemePermitted(final String identity, final UserAuthenticationScheme scheme) {
        try {
            return appCtx.getAllowedUserAuthenticationSchemes(identity).contains(scheme);
        } catch (ConfigurationException e) {
            throw new ConfigurationRuntimeException(e);
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
        try {
            return appCtx.getAllowedKeyExchangeSchemes(identity).contains(scheme);
        } catch (ConfigurationException e) {
            throw new ConfigurationRuntimeException(e);
        }
    }
    
    @Override
    public String toString() {
        return SharedUtil.toString(this, entityId);
    }

    /** Local client entity identity. */
    protected final String entityId;
    /** app context. */
    protected final AppContext appCtx;
}
