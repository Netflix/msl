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

import com.netflix.msl.keyx.AsymmetricWrappedExchange;
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
 * Asymmetric Wrapped Key Exchange handle class
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class AsymmetricWrappedExchangeHandle extends KeyExchangeHandle {
    /**
     * default constructor
     */
    public AsymmetricWrappedExchangeHandle() {
        super(KeyExchangeScheme.ASYMMETRIC_WRAPPED);
    }

    @Override
    public KeyRequestData getKeyRequestData(final AppContext appCtx, final CmdArguments args)
        throws IllegalCmdArgumentException
    {
        final AsymmetricWrappedExchange.RequestData.Mechanism m = getKeyExchangeMechanism(
            AsymmetricWrappedExchange.RequestData.Mechanism.class, args.getKeyExchangeMechanism());
        if (aweKeyPair == null) {
            aweKeyPair = appCtx.generateAsymmetricWrappedExchangeKeyPair();
        }
        return new AsymmetricWrappedExchange.RequestData(DEFAULT_AWE_KEY_PAIR_ID, m, aweKeyPair.getPublic(), aweKeyPair.getPrivate());
    }

    @Override
    public KeyExchangeFactory getKeyExchangeFactory(final AppContext appCtx, final CmdArguments args, final AuthenticationUtils authutils) {
        return new AsymmetricWrappedExchange(authutils);
    }

    /**
     * Cached RSA Key Pair for asymmetric key wrap key exchange to avoid expensive key pair generation.
     * This is an optimization specific to this application, to avoid annoying delays in generating
     * 4096-bit RSA key pairs. Real-life implementations should not re-use key wrapping keys
     * too many times.
     */
    private KeyPair aweKeyPair = null;
    /** default asymmetric key wrap exchange key pair id - the value should not matter */
    private static final String DEFAULT_AWE_KEY_PAIR_ID = "default_awe_key_id";
}
