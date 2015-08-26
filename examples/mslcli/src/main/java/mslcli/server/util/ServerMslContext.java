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

package mslcli.server.util;

import javax.crypto.SecretKey;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.crypto.SymmetricCryptoContext;
import com.netflix.msl.tokens.TokenFactory;

import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.Triplet;
import mslcli.common.util.AppContext;
import mslcli.common.util.CommonMslContext;
import mslcli.common.util.ConfigurationException;
import mslcli.server.ServerMslConfig;
import mslcli.server.tokens.ServerTokenFactory;

/**
 * <p>Server MSL context. It represents configurations specific to a given service entity ID.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public class ServerMslContext extends CommonMslContext {
    /**
     * <p>Create a new server MSL context.</p>
     * 
     * @param appCtx application context
     * @param mslCfg server MSL configuration.
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public ServerMslContext(final AppContext appCtx, final ServerMslConfig mslCfg) throws ConfigurationException, IllegalCmdArgumentException {
        super(appCtx, mslCfg);
        
        // MSL crypto context.
        final Triplet<SecretKey,SecretKey,SecretKey> mslKeys = appCtx.getMslKeys();
        this.mslCryptoContext = new SymmetricCryptoContext(this, mslCfg.getEntityId(), mslKeys.x, mslKeys.y, mslKeys.z);

        // key token factory
        this.tokenFactory = new ServerTokenFactory(appCtx);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslCryptoContext()
     */
    @Override
    public ICryptoContext getMslCryptoContext() throws MslCryptoException {
        return mslCryptoContext;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getTokenFactory()
     */
    @Override
    public TokenFactory getTokenFactory() {
        return tokenFactory;
    }

    /** MSL crypto context */
    private final ICryptoContext mslCryptoContext;
    /** MSL token factory */
    private final TokenFactory tokenFactory;
}
