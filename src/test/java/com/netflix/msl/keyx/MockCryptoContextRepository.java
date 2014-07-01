/**
 * Copyright (c) 2013-2014 Netflix, Inc.  All rights reserved.
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
package com.netflix.msl.keyx;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.crypto.ICryptoContext;

/**
 * This crypto context repository provides a simple in-memory store of wrapping
 * key crypto contexts.
 * 
 * This class is thread-safe.
 * 
 * @author Wesley Miaw <wmiaw@netflix.com>
 */
public class MockCryptoContextRepository implements WrapCryptoContextRepository {
    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.JsonWebEncryptionLadderExchange.CryptoContextRepository#addCryptoContext(byte[], com.netflix.msl.crypto.ICryptoContext)
     */
    @Override
    public synchronized void addCryptoContext(final byte[] wrapdata, final ICryptoContext cryptoContext) {
        cryptoContexts.put(wrapdata, cryptoContext);
        this.wrapdata = wrapdata;
    }

    @Override
    public synchronized ICryptoContext getCryptoContext(final byte[] wrapdata) {
        return cryptoContexts.get(wrapdata);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.keyx.JsonWebEncryptionLadderExchange.CryptoContextRepository#removeCryptoContext(byte[])
     */
    @Override
    public synchronized void removeCryptoContext(final byte[] wrapdata) {
        cryptoContexts.remove(wrapdata);
        if (Arrays.equals(this.wrapdata, wrapdata))
            this.wrapdata = null;
    }
    
    /**
     * @return the newest wrap data or null if there is none.
     */
    public synchronized byte[] getWrapdata() {
        return wrapdata;
    }
    
    /**
     * Clear the repository of all state data.
     */
    public synchronized void clear() {
        cryptoContexts.clear();
        wrapdata = null;
    }

    /** Newest wrap data. */
    private byte[] wrapdata;
    /** Map of wrap data onto crypto contexts. */
    private final Map<byte[],ICryptoContext> cryptoContexts = new HashMap<byte[],ICryptoContext>();
}
