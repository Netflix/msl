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

package mslcli.common.util;

import com.netflix.msl.crypto.ICryptoContext;

import com.netflix.msl.keyx.WrapCryptoContextRepository;

/**
 * WrapCryptoContextRepositoryWrapper class makes pass-through calls to WrapCryptoContextRepositoryHandle.
 * Extending this class allows intercepting selected methods in order to customize their behavior,
 * including reporting, testing, etc.
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public class WrapCryptoContextRepositoryWrapper implements WrapCryptoContextRepositoryHandle {
    private volatile WrapCryptoContextRepositoryHandle rep;

    /**
     * package-private so only AppContext can call it
     */
    final void setWrapCryptoContextRepository(final WrapCryptoContextRepositoryHandle rep) {
        if (rep == null) {
            throw new IllegalArgumentException("NULL WrapCryptoContextRepository");
        }
        if (rep instanceof WrapCryptoContextRepositoryWrapper) {
            throw new IllegalArgumentException("WrapCryptoContextRepository is WrapCryptoContextRepositoryWrapper instance");
        }
        this.rep = rep;
    }

    /**
     * @see com.netflix.msl.keyx.WrapCryptoContextRepository.addCryptoContext()
     */
    @Override
    public void addCryptoContext(final byte[] wrapdata, final ICryptoContext cryptoContext) {
        rep.addCryptoContext(wrapdata, cryptoContext);
    }

    /**
     * @see com.netflix.msl.keyx.WrapCryptoContextRepository.getCryptoContext()
     */
    @Override
    public ICryptoContext getCryptoContext(final byte[] wrapdata) {
        return rep.getCryptoContext(wrapdata);
    }

    /**
     *@see com.netflix.msl.keyx.WrapCryptoContextRepository.removeCryptoContext()
     */
    @Override
    public void removeCryptoContext(final byte[] wrapdata) {
        rep.removeCryptoContext(wrapdata);
    }

    @Override
    public byte[] getLastWrapdata() {
        return rep.getLastWrapdata();
    }
}
