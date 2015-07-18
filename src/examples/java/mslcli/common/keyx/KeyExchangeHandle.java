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
import java.util.List;

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
            throw new IllegalCmdArgumentException(String.format("Missing Key Exchange Mechanism for %s: Valid %s",
                scheme.name(), values));
        }
        try {
            return Enum.valueOf(clazz, kxmName.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalCmdArgumentException(String.format("Illegal Key Exchange %s for %s, Valid %s",
                scheme.name(), kxmName.trim(), values));
        }
    }

    /**
     * @return wrapping key repository, for applicable key exchanges
     */
    public WrapCryptoContextRepositoryHandle getWrapCryptoContextRepository() {
        throw new UnsupportedOperationException();
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
        protected AppWrapCryptoContextRepository(final AppContext appCtx, final String entityId, final KeyExchangeScheme scheme) {
            super(new SimpleWrapCryptoContextRepository(entityId, scheme));
            this.appCtx = appCtx;
            this.id = String.format("WrapCryptoContextRepo[%s %s]", entityId, scheme.toString());
        }

        @Override
        public void addCryptoContext(final byte[] wrapdata, final ICryptoContext cryptoContext) {
            appCtx.info(String.format("%s: addCryptoContext %s", id, cryptoContext.getClass().getName()));
            super.addCryptoContext(wrapdata, cryptoContext);
        }

        @Override
        public ICryptoContext getCryptoContext(final byte[] wrapdata) {
            appCtx.info(String.format("%s: getCryptoContext", id));
            return super.getCryptoContext(wrapdata);
        }

        @Override
        public void removeCryptoContext(final byte[] wrapdata) {
            appCtx.info(String.format("%s: removeCryptoContext", id));
            super.removeCryptoContext(wrapdata);
        }
        /** application context */
        private final AppContext appCtx;
        /** id for this instance */
        private final String id;
    }

    /** key exchange scheme */
    protected final KeyExchangeScheme scheme;
}
