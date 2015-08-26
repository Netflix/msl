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

package mslcli.client;

import mslcli.client.util.ClientAuthenticationUtils;
import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.MslConfig;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;

/**
 * <p>
 * The configuration class for specific MSl client entity ID.
 * Each time the app changes client entity ID, new instance
 * needs to be created.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class ClientMslConfig extends MslConfig {
    /**
     * Constructor.
     *
     * @param appCtx application context
     * @param args command line arguments
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public ClientMslConfig(final AppContext appCtx, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        super(appCtx, args, new ClientAuthenticationUtils(args.getEntityId(), appCtx));
    }
}
