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

package mslcli.common.userauth;

import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;

/**
 * <p>
 * Common abstract class for plugin implementation of user various authentication mechanisms
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public abstract class UserAuthenticationHandle {
    /** user authentication scheme */
    private final UserAuthenticationScheme scheme;

    /**
     * @param scheme user authentication scheme
     */
    public UserAuthenticationHandle(final UserAuthenticationScheme scheme) {
        this.scheme = scheme;
    }
 
    /**
     * @return entity authentication scheme
     */
    public final UserAuthenticationScheme getScheme() {
        return scheme;
    }

    /**
     * @param appCtx application context
     * @param args command line arguments
     * @return entity authentication data to be included into a message
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public abstract UserAuthenticationData getUserAuthenticationData(final AppContext appCtx, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException;

    /**
     * @param appCtx application context
     * @param args command line arguments
     * @param authutils authentication utilities
     * @return entity authentication factory
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public abstract UserAuthenticationFactory getUserAuthenticationFactory(final AppContext appCtx, final CmdArguments args, final AuthenticationUtils authutils)
        throws ConfigurationException, IllegalCmdArgumentException;
}
