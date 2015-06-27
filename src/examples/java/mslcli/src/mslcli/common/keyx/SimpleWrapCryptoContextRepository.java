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
import java.util.HashMap;
import java.util.Map;

import com.netflix.msl.crypto.ICryptoContext;

import com.netflix.msl.keyx.WrapCryptoContextRepository;

/**
 * Memory-backed Wrap Crypto Context Repository
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public final class SimpleWrapCryptoContextRepository implements WrapCryptoContextRepository {
    private final Map<ByteBuffer,ICryptoContext> repository = new HashMap<ByteBuffer,ICryptoContext>();

    /**
     * @see com.netflix.msl.keyx.WrapCryptoContextRepository.addCryptoContext()
     */
    @Override
    public void addCryptoContext(final byte[] wrapdata, final ICryptoContext cryptoContext) {
        repository.put(ByteBuffer.wrap(wrapdata), cryptoContext);
    }

    /**
     * @see com.netflix.msl.keyx.WrapCryptoContextRepository.getCryptoContext()
     */
    @Override
    public ICryptoContext getCryptoContext(final byte[] wrapdata) {
        return repository.get(ByteBuffer.wrap(wrapdata));
    }

    /**
     *@see com.netflix.msl.keyx.WrapCryptoContextRepository.removeCryptoContext()
     */
    @Override
    public void removeCryptoContext(final byte[] wrapdata) {
        repository.remove(ByteBuffer.wrap(wrapdata));
    }
}
