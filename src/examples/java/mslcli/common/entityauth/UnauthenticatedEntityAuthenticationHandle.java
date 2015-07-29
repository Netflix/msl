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

package mslcli.common.entityauth;

import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationData;
import com.netflix.msl.entityauth.UnauthenticatedAuthenticationFactory;
import com.netflix.msl.util.AuthenticationUtils;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
 
/**
 * <p>
 * Plugin implementation for generating unauthenticated entity authentication data and factory
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class UnauthenticatedEntityAuthenticationHandle extends EntityAuthenticationHandle {
    /**
     * ctor
     */
    public UnauthenticatedEntityAuthenticationHandle() {
        super(EntityAuthenticationScheme.NONE);
    }

    @Override
    public EntityAuthenticationData getEntityAuthenticationData(final AppContext appCtx, final CmdArguments args)
        throws IllegalCmdArgumentException
    {
        return new UnauthenticatedAuthenticationData(args.getEntityId());
    }

    @Override
    public EntityAuthenticationFactory getEntityAuthenticationFactory(final AppContext appCtx, final CmdArguments args, final AuthenticationUtils authutils)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        return new UnauthenticatedAuthenticationFactory(authutils);
    }
}
