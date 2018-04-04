/**
 * Copyright (c) 2014-2018 Netflix, Inc.  All rights reserved.
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

package mslcli.server;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.MslConfig;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.server.util.ServerAuthenticationUtils;

/**
 * <p>
 * The configuration class for MSl server, created per given server entity identity.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class ServerMslConfig extends MslConfig {
    /**
     * Constructor.
     *
     * @param appCtx application context.
     * @param args command line arguments
     * @throws ConfigurationException if some configuration parameters required for initialization are missing, invalid, or mutually inconsistent
     * @throws IllegalCmdArgumentException if some command line parameters required for initialization are missing, invalid, or mutually inconsistent
     */
    public ServerMslConfig(final AppContext appCtx, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        super(appCtx, args, new ServerAuthenticationUtils(args.getEntityId(), appCtx));
    }
}
