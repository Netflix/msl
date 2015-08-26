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

import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.EmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslStore;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
import mslcli.common.Pair;
import mslcli.common.util.ConfigurationException;

/**
 * <p>
 * Plugin implementation for email-password user authentication functionality
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class EmailPasswordUserAuthenticationHandle extends UserAuthenticationHandle {
    /**
     * default ctor
     */
    public EmailPasswordUserAuthenticationHandle() {
        super(UserAuthenticationScheme.EMAIL_PASSWORD);
    }

    @Override
    public UserAuthenticationData getUserAuthenticationData(final AppContext appCtx, final CmdArguments args, final MslStore mslStore)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        final String userId = args.getUserId();
        if (userId == null || userId.trim().length() == 0)
            return null;
        final boolean interactive = args.isInteractive();
        try {
            final Pair<String,String> ep = appCtx.getProperties().getEmailPassword(userId);
            return new EmailPasswordAuthenticationData(ep.x, ep.y);
        } catch (ConfigurationException e) {
            final String email = getHandleArg(args, "email");
            final String pwd = getHandlePwdArg(args, "password");
            return new EmailPasswordAuthenticationData(email, pwd);
        }
    }

    @Override
    public UserAuthenticationFactory getUserAuthenticationFactory(final AppContext appCtx, final CmdArguments args, final AuthenticationUtils authutils)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        return new EmailPasswordAuthenticationFactory(appCtx.getEmailPasswordStore(), authutils);
    }
}
