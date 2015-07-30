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

import mslcli.common.util.AppContext;
import mslcli.common.util.CommonAuthenticationUtils;
import mslcli.common.util.ConfigurationException;

/**
 * <p>
 *    Utility telling which entity authentication, user authentication,
 *    and key exchange schemes are permitted/supported for a given entity.
 *    So far, the base class functionality is sufficient.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ClientAuthenticationUtils extends CommonAuthenticationUtils {
    /**
     * <p>Create a new authentication utils instance for the specified client identity.</p>
     * 
     * @param clientId local client entity identity.
     * @param appCtx application context
     * @throws ConfigurationException
     */
    public ClientAuthenticationUtils(final String clientId, final AppContext appCtx) throws ConfigurationException {
        super(clientId, appCtx);
    }
}
