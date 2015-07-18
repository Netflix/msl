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

import java.io.Console;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.userauth.EmailPasswordAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationData;

import mslcli.client.util.ClientAuthenticationUtils;
import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.MslConfig;
import mslcli.common.Pair;
import mslcli.common.keyx.KeyExchangeHandle;
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

    /**
     * @param kxsName the name of key exchange scheme
     * @param kxmName the name of key exchange scheme mechanism
     * @return key request data
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     * @throws MslKeyExchangeException
     */
    public KeyRequestData getKeyRequestData()
        throws ConfigurationException, IllegalCmdArgumentException, MslKeyExchangeException
    {
        final String kxsName = args.getKeyExchangeScheme();
        if (kxsName == null || kxsName.trim().isEmpty()) {
            throw new IllegalArgumentException("NULL Key Exchange Type");
        }
        final String kxmName = args.getKeyExchangeMechanism();
        appCtx.info(String.format("%s: Generating KeyRequestData{%s %s}", this, kxsName.trim(), (kxmName != null) ? kxmName.trim() : null));

        for (final KeyExchangeHandle kxh : appCtx.getKeyExchangeHandles()) {
            if (kxh.getScheme().name().equals(kxsName))
                return kxh.getKeyRequestData(appCtx, args);
        }
        final List<String> schemes = new ArrayList<String>();
        for (final KeyExchangeHandle kxh : appCtx.getKeyExchangeHandles())
            schemes.add(kxh.getScheme().name());
        throw new IllegalCmdArgumentException(String.format("Unsupported Key Exchange Scheme %s, Supported: %s", kxsName, schemes));
    }

    /**
     * @param userId user identity
     * @param interactive true in the interactive mode
     * @return  user authentication data
     */
    public UserAuthenticationData getUserAuthenticationData(final String userId, boolean interactive) {
        appCtx.info(String.format("%s: Requesting UserAuthenticationData, UserId %s, Interactive %b", this, userId, interactive));
        if (userId != null) {
            try {
                final Pair<String,String> ep = appCtx.getProperties().getEmailPassword(userId);
                return new EmailPasswordAuthenticationData(ep.x, ep.y);
            } catch (ConfigurationException e) {
                if (interactive) {
                    final Console cons = System.console();
                    if (cons != null) {
                        final String email = cons.readLine("Email> ");
                        final char[] pwd = cons.readPassword("Password> ");
                        return new EmailPasswordAuthenticationData(email, new String(pwd));
                    } else {
                        throw new IllegalArgumentException("Invalid Email-Password Configuration for User " + userId);
                    }
                } else {
                    throw new IllegalArgumentException("Invalid Email-Password Configuration for User " + userId);
                }
            }
        } else {
            return null;
        }
    }

    @Override
    public String toString() {
        return String.format("ClientMslConfig[%s]", entityId);
    }
}
