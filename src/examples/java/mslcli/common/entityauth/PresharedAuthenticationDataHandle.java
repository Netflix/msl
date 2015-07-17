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
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.entityauth.PresharedAuthenticationData;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
 
/**
 * <p>
 * Interface facilitating plugin implementation for generating entity authentication data
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class PresharedAuthenticationDataHandle implements AuthenticationDataHandle {
    @Override
    public EntityAuthenticationScheme getScheme() {
        return EntityAuthenticationScheme.PSK;
    }

    @Override
    public EntityAuthenticationData getEntityAuthenticationData(final AppContext appCtx, final CmdArguments args)
        throws IllegalCmdArgumentException
    {
        return new PresharedAuthenticationData(args.getEntityId());
    }
};
