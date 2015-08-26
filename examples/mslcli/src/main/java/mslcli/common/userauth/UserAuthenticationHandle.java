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

import java.io.Console;
import java.util.Map;

import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslStore;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.SharedUtil;

/**
 * <p>
 * Common abstract class for plugin implementation of user authentication mechanisms
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
     * @param mslStore MSL store 
     * @return entity authentication data to be included into a message
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public abstract UserAuthenticationData getUserAuthenticationData(final AppContext appCtx, final CmdArguments args, final MslStore mslStore)
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

    /**
     * @param appCtx application context
     * @param args runtime arguments
     * @return current user id
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public String getUserId(final AppContext appCtx, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        return args.getUserId();
    }

    /**
     * @param args runtime arguments
     * @param name handle-specific argument name, with "-ext.uah.scheme." prefix implied
     * @return argument value
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    protected String getHandleArg(final CmdArguments args, final String name)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        return _getHandleArg(args, name, false);
    }

    /**
     * @param args runtime arguments
     * @param name handle-specific argument name, with "-ext.uah.scheme." prefix implied
     * @return argument value
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    protected String getHandlePwdArg(final CmdArguments args, final String name)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        return _getHandleArg(args, name, true);
    }

    /**
     * @param args runtime arguments
     * @param name handle-specific argument name, with "-ext.uah.scheme." prefix implied
     * @param isPassword true if the argument is password, so its value should not be echoed
     * @return argument value
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    private String _getHandleArg(final CmdArguments args, final String name, final boolean isPassword)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        if (args == null)
            throw new IllegalArgumentException(String.format("%s: NULL arguments", this));
        if (name == null || name.length() == 0)
            throw new IllegalArgumentException(String.format("%s: NULL or empty property name", this));

        final String prefix = "uah." + scheme.toString().toLowerCase();

        final String value;
        final Map<String,String> m = args.getExtensionProperties(prefix);
        if (!m.isEmpty()) {
            value = m.get(name);
            if (value == null)
                throw new IllegalCmdArgumentException(String.format("%s: Missing Extension Property \"%s.%s\" - %s", this, prefix, name, m.toString()));
        } else if (args.isInteractive()) {
           final Console cons = System.console();
            if (cons != null) {
                if (isPassword)
                    value = new String(cons.readPassword("%s.%s> ", prefix, name));
                else
                    value = cons.readLine("%s.%s> ", prefix, name);
            } else {
                throw new IllegalCmdArgumentException(String.format("%s: Cannot get Console", this));
            }
        } else {
            throw new IllegalCmdArgumentException(String.format("%s: No support in non-interactive mode and without \"%s.%s\" extension property",
                this, prefix, name));
        }
        return value;
    }

    @Override
    public final String toString() {
        return SharedUtil.toString(this, scheme);
    }
}
