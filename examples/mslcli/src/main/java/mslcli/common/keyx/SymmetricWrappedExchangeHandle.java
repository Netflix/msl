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

package mslcli.common.keyx;

import java.security.KeyPair;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.util.AuthenticationUtils;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;

/**
 * <p>
 * Symmetric Wrapped Key Exchange handle class
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SymmetricWrappedExchangeHandle extends KeyExchangeHandle {
    /**
     * default constructor
     */
    public SymmetricWrappedExchangeHandle() {
        super(KeyExchangeScheme.SYMMETRIC_WRAPPED);
    }

    @Override
    public KeyRequestData getKeyRequestData(final AppContext appCtx, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException, MslKeyExchangeException
    {
        final SymmetricWrappedExchange.KeyId keyId = getKeyExchangeMechanism(
            SymmetricWrappedExchange.KeyId.class, args.getKeyExchangeMechanism());
        return new SymmetricWrappedExchange.RequestData(keyId);

    }

    @Override
    public KeyExchangeFactory getKeyExchangeFactory(final AppContext appCtx, final CmdArguments args, final AuthenticationUtils authutils) {
        return new SymmetricWrappedExchange(authutils);
    }
}
