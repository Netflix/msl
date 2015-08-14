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

package mslcli.client.util;

import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ClientMslCryptoContext;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.tokens.ClientTokenFactory;
import com.netflix.msl.tokens.TokenFactory;

import mslcli.client.ClientMslConfig;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
import mslcli.common.util.CommonMslContext;
import mslcli.common.util.ConfigurationException;

/**
 * <p>
 * Sample client MSL context for clients talking to trusted network servers.
 * It represents configurations specific to a given client entity ID.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class ClientMslContext extends CommonMslContext {
    
    /**
     * <p>Create a new MSL context.</p>
     * 
     * @param appCtx application context
     * @param mslCfg encapsulation of MSL configuration parameters
     * @throws ConfigurationException if some configuration parameters required for initialization are missing, invalid, or mutually inconsistent
     * @throws IllegalCmdArgumentException if some command line arguments required for initialization are missing, invalid, or mutually inconsistent
     */
    public ClientMslContext(final AppContext appCtx, final ClientMslConfig mslCfg)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        super(appCtx, mslCfg);
        
        /* MSL crypto context. Since MSL client does not encrypt/decrypt master tokens,
         * ClientMslCryptoContext is used. It has all dummy methods. This class
         * is defined in MSL core.
         */
        this.mslCryptoContext = new ClientMslCryptoContext();

        // key token factory
        this.tokenFactory = new ClientTokenFactory();
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

    /** MSL crypt context */
    private final ICryptoContext mslCryptoContext;
    /** client token factory */
    private final TokenFactory tokenFactory;
}
