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

import java.nio.ByteBuffer;
import java.util.LinkedHashMap;
import java.util.Map;

import com.netflix.msl.crypto.ICryptoContext;

import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.WrapCryptoContextRepository;

import mslcli.common.util.SharedUtil;
import mslcli.common.util.WrapCryptoContextRepositoryHandle;

/**
 * <p>
 * Memory-backed Wrap Crypto Context Repository.
 * Instance is specific to entity ID and key exchange scheme.
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class SimpleWrapCryptoContextRepository implements WrapCryptoContextRepositoryHandle {
    /** mappings between wrapping key blob and crypto context */
    private final Map<ByteBuffer,ICryptoContext> repository = new LinkedHashMap<ByteBuffer,ICryptoContext>();
    /** entity identity of this repository */
    protected final String entityId;
    /** key exchange scheme of this repository */
    protected final KeyExchangeScheme scheme;

    /**
     * Ctor
     * @param entityId entity ID
     * @param scheme key exchange scheme
     */
    public SimpleWrapCryptoContextRepository(final String entityId, final KeyExchangeScheme scheme) {
        this.entityId = entityId;
        this.scheme = scheme;
    }

    /**
     * @see com.netflix.msl.keyx.WrapCryptoContextRepository#addCryptoContext(byte[],ICryptoContext)
     */
    @Override
    public synchronized void addCryptoContext(final byte[] wrapdata, final ICryptoContext cryptoContext) {
        repository.put(ByteBuffer.wrap(wrapdata), cryptoContext);
    }

    /**
     * @see com.netflix.msl.keyx.WrapCryptoContextRepository#getCryptoContext(byte[])
     */
    @Override
    public synchronized ICryptoContext getCryptoContext(final byte[] wrapdata) {
        return repository.get(ByteBuffer.wrap(wrapdata));
    }

    /**
     * @see com.netflix.msl.keyx.WrapCryptoContextRepository#removeCryptoContext(byte[])
     */
    @Override
    public synchronized void removeCryptoContext(final byte[] wrapdata) {
        repository.remove(ByteBuffer.wrap(wrapdata));
    }

    /**
     * @see mslcli.common.util.WrapCryptoContextRepositoryHandle#getLastWrapdata()
     */
    @Override
    public synchronized byte[] getLastWrapdata() {
        ByteBuffer bb1 = null;
        for (ByteBuffer bb : repository.keySet()) {
            bb1 = bb;
        }
        return (bb1 != null) ? bb1.array() : null;
    }

    @Override
    public String toString() {
        return SharedUtil.toString(this, entityId, scheme);
    }
}
