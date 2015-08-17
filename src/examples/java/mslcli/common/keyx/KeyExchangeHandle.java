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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.keyx.WrapCryptoContextRepository;
import com.netflix.msl.util.AuthenticationUtils;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.SharedUtil;
import mslcli.common.util.WrapCryptoContextRepositoryHandle;
import mslcli.common.util.WrapCryptoContextRepositoryWrapper;

/**
 * <p>
 * Handle to facilitate plugin design for support of arbitrary key exchange schemes.
 * Derived classes must have default constructors.
 * </p>
 *
 * @author Vadim Spector <vspector@netflix.com>
 */

public abstract class KeyExchangeHandle {
    /**
     * @param scheme key exchange scheme
     */
    protected KeyExchangeHandle(final KeyExchangeScheme scheme) {
        this.scheme = scheme;
    }

    /**
     * @return key exchange scheme
     */
    public final KeyExchangeScheme getScheme() {
        return scheme;
    }

    /**
     * @param appCtx application context
     * @param args command line arguments
     * @return key exchange request data
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     * @throws MslKeyExchangeException
     */
    public abstract KeyRequestData getKeyRequestData(final AppContext appCtx, final CmdArguments args)
        throws ConfigurationException, IllegalCmdArgumentException, MslKeyExchangeException;

    /**
     * @param appCtx application context
     * @param args command line arguments
     * @param authutils authentication utilities
     * @return key exchange request data
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public abstract KeyExchangeFactory getKeyExchangeFactory(final AppContext appCtx, final CmdArguments args, final AuthenticationUtils authutils)
        throws ConfigurationException, IllegalCmdArgumentException;

   /**
     * convenience method
     * @param clazz class defining Enum values for key exchange mechanisms for a given key exchange scheme
     * @param kxmName key exchange mechanism name
     * @param <T> enumerated type
     * @return key eachange mechanism Enum value
     * @throws IllegalCmdArgumentException
     */
    protected <T extends Enum<T>> T getKeyExchangeMechanism(final Class<T> clazz, final String kxmName)
        throws IllegalCmdArgumentException
    {
        final List<T> values = Arrays.asList(clazz.getEnumConstants());
        if (kxmName == null || kxmName.trim().isEmpty()) {
            throw new IllegalCmdArgumentException(String.format("KeyExchange[%s]: Unspecified Mechanism, Valid %s",
                scheme.name(), values));
        }
        try {
            return Enum.valueOf(clazz, kxmName.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalCmdArgumentException(String.format("KeyExchange[%s]: Illegal Mechanism %s, Valid %s",
                scheme.name(), kxmName.trim(), values));
        }
    }

    @Override
    public final String toString() {
        return SharedUtil.toString(this, scheme);
    }

    /**
     * extension of WrapCryptoContextRepositoryWrapper class to intercept and report calls
     */
    protected static final class AppWrapCryptoContextRepository extends WrapCryptoContextRepositoryWrapper {
        /**
         * @param appCtx application context
         * @param entityId entity identity
         * @param scheme key exchange scheme
         */
        public AppWrapCryptoContextRepository(final AppContext appCtx, final String entityId, final KeyExchangeScheme scheme) {
            super(new SimpleWrapCryptoContextRepository(entityId, scheme));
            this.appCtx = appCtx;
        }

        @Override
        public void addCryptoContext(final byte[] wrapdata, final ICryptoContext cryptoContext) {
            appCtx.info(String.format("%s: addCryptoContext(%s %s)", this, SharedUtil.getWrapDataInfo(wrapdata), SharedUtil.toString(cryptoContext)));
            super.addCryptoContext(wrapdata, cryptoContext);
        }

        @Override
        public ICryptoContext getCryptoContext(final byte[] wrapdata) {
            appCtx.info(String.format("%s: getCryptoContext(%s)", this, SharedUtil.getWrapDataInfo(wrapdata)));
            return super.getCryptoContext(wrapdata);
        }

        @Override
        public void removeCryptoContext(final byte[] wrapdata) {
            appCtx.info(String.format("%s: delCryptoContext(%s)", this, SharedUtil.getWrapDataInfo(wrapdata)));
            super.removeCryptoContext(wrapdata);
        }

        /** application context */
        private final AppContext appCtx;
    }

    /**
     * Lazy initialization of WrapCryptoContextRepositoryHandle for a given entity identity
     *
     * @param appCtx application context
     * @param args command line arguments
     * @return WrapCryptoContextRepositoryHandle instance
     * @throws IllegalCmdArgumentException
     */

    protected WrapCryptoContextRepositoryHandle getRepo(final AppContext appCtx, final CmdArguments args)
        throws IllegalCmdArgumentException
    {
        synchronized (rep) {
            WrapCryptoContextRepositoryHandle r = rep.get(args.getEntityId());
            if (r == null)
                rep.put(args.getEntityId(), r = new AppWrapCryptoContextRepository(appCtx, args.getEntityId(), getScheme()));
            return r;
        }
    }

    /** key exchange scheme */
    protected final KeyExchangeScheme scheme;
    /** mapping of key wrapping data to crypto context */
    private final Map<String,WrapCryptoContextRepositoryHandle> rep = new HashMap<String,WrapCryptoContextRepositoryHandle>();
}
