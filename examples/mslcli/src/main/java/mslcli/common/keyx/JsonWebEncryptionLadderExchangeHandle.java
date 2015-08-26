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
import java.util.HashMap;
import java.util.Map;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.WrapCryptoContextRepository;
import com.netflix.msl.util.AuthenticationUtils;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.WrapCryptoContextRepositoryHandle;

/**
 * <p>
 * Json Web Encryption Ladder Key Exchange Handle class
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class JsonWebEncryptionLadderExchangeHandle extends KeyExchangeHandle {
    /**
     * default constructor
     */
    public JsonWebEncryptionLadderExchangeHandle() {
        super(KeyExchangeScheme.JWE_LADDER);
    }

    @Override
    public KeyRequestData getKeyRequestData(final AppContext appCtx, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException, MslKeyExchangeException
    {
        final JsonWebEncryptionLadderExchange.Mechanism m = getKeyExchangeMechanism(
            JsonWebEncryptionLadderExchange.Mechanism.class, args.getKeyExchangeMechanism());
        final byte[] wrapdata;
        if (m == JsonWebEncryptionLadderExchange.Mechanism.WRAP) {
            wrapdata = getRepo(appCtx, args).getLastWrapdata();
            if (wrapdata == null)
                throw new IllegalCmdArgumentException(String.format("No Key Wrapping Data Found for {%s %s}", getScheme().name(), m));
        } else {
            wrapdata = null;
        }
        return new JsonWebEncryptionLadderExchange.RequestData(m, wrapdata);
    }

    @Override
    public KeyExchangeFactory getKeyExchangeFactory(final AppContext appCtx, final CmdArguments args, final AuthenticationUtils authutils)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        return new JsonWebEncryptionLadderExchange(getRepo(appCtx, args), authutils);
    }
}
