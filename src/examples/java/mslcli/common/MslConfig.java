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

package mslcli.common;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedAuthenticationFactory;
import com.netflix.msl.entityauth.PresharedKeyStore;
import com.netflix.msl.entityauth.RsaAuthenticationFactory;
import com.netflix.msl.entityauth.RsaStore;
import com.netflix.msl.keyx.AsymmetricWrappedExchange;
import com.netflix.msl.keyx.DiffieHellmanExchange;
import com.netflix.msl.keyx.JsonWebEncryptionLadderExchange;
import com.netflix.msl.keyx.JsonWebKeyLadderExchange;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.SymmetricWrappedExchange;
import com.netflix.msl.keyx.WrapCryptoContextRepository;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.tokens.ServiceToken;
import com.netflix.msl.userauth.EmailPasswordAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

import mslcli.common.CmdArguments;
import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.entityauth.AuthenticationDataHandle;
import mslcli.common.keyx.SimpleWrapCryptoContextRepository;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.MslStoreWrapper;
import mslcli.common.util.SharedUtil;
import mslcli.common.util.WrapCryptoContextRepositoryHandle;
import mslcli.common.util.WrapCryptoContextRepositoryWrapper;

/**
 * <p>
 * The common configuration class for MSl client and server.
 * Instance of this class is specific to a given entity ID.
 * If entity ID changes, new instance of MslConfig must be used.
 * </p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public abstract class MslConfig {
    /**
     * Ctor
     * @param appCtx application context
     * @param args command line arguments
     * @param entityAuthData entity authentication data
     * @param authutils authentication utils
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    protected MslConfig(final AppContext appCtx,
                        final CmdArguments args,
                        final AuthenticationUtils authutils)
        throws ConfigurationException, IllegalCmdArgumentException
    {
        // set application context
        this.appCtx = appCtx;

        // set arguments
        this.args = args;

        // set entity ID
        this.entityId = args.getEntityId();

        // set MslStore
        if (args.getMslStorePath() != null) {
            this.mslStorePath = args.getMslStorePath().replace("{eid}", entityId);
        } else {
            this.mslStorePath = null;
        }
        this.mslStoreWrapper = new AppMslStoreWrapper(appCtx, entityId, initMslStore(appCtx, mslStorePath));

        // Entity authentication.
        this.entityAuthDataHandle = appCtx.getAuthenticationDataHandle(args.getEntityAuthenticationScheme());
        if (this.entityAuthDataHandle == null)
            throw new IllegalCmdArgumentException(String.format("Entity %s: no support for entity auth scheme %s", entityId, args.getEntityAuthenticationScheme()));

        // Entity authentication factories.
        this.entityAuthFactories = new HashSet<EntityAuthenticationFactory>();
        this.entityAuthFactories.add(new PresharedAuthenticationFactory(appCtx.getPresharedKeyStore(), authutils));
        this.entityAuthFactories.add(new RsaAuthenticationFactory(appCtx.getRsaStore(), authutils));

        // User authentication factories.
        this.userAuthFactories = new HashSet<UserAuthenticationFactory>();
        this.userAuthFactories.add(new EmailPasswordAuthenticationFactory(appCtx.getEmailPasswordStore(), authutils));

        // wrapping key repositories per keyexchange scheme
        this.wrapCryptoContextRepositories = new HashMap<KeyExchangeScheme,WrapCryptoContextRepositoryHandle>();
        final WrapCryptoContextRepositoryHandle jwe_h = new AppWrapCryptoContextRepository(appCtx, entityId, KeyExchangeScheme.JWE_LADDER);
        final WrapCryptoContextRepositoryHandle jwk_h = new AppWrapCryptoContextRepository(appCtx, entityId, KeyExchangeScheme.JWK_LADDER);
        this.wrapCryptoContextRepositories.put(KeyExchangeScheme.JWE_LADDER, jwe_h);
        this.wrapCryptoContextRepositories.put(KeyExchangeScheme.JWK_LADDER, jwk_h);

        // Key exchange factories.
        this.keyxFactories = getKeyExchangeFactorySet(
            new AsymmetricWrappedExchange(authutils),
            new SymmetricWrappedExchange(authutils),
            new DiffieHellmanExchange(appCtx.getDiffieHellmanParameters(), authutils),
            new JsonWebEncryptionLadderExchange(jwe_h, authutils),
            new JsonWebKeyLadderExchange(jwk_h, authutils)
        );
    }

    /**
     * Initialize MslStore
     *
     * @param appCtx application context
     * @param mslStorePath MSL store path
     * @return MSL store
     * @throws ConfigurationException
     */
    private static SimpleMslStore initMslStore(final AppContext appCtx, final String mslStorePath) throws ConfigurationException {
        if (mslStorePath == null) {
            appCtx.info("Creating Non-Persistent MSL Store");
            return new SimpleMslStore();
        }

        try {
            final File f = new File(mslStorePath);
            if (f.isFile()) {
                appCtx.info("Loading MSL Store from " + mslStorePath);
                return (SimpleMslStore)SharedUtil.unmarshalMslStore(SharedUtil.readFromFile(mslStorePath));
            } else if (f.exists()){
                throw new IllegalArgumentException("MSL Store Path Exists but not a File: " + mslStorePath);
            } else {
                appCtx.info("Creating Empty MSL Store " + mslStorePath);
                return new SimpleMslStore();
            }
        } catch (Exception e) {
            throw new ConfigurationException("Error reading MSL Store File " + mslStorePath, e);
        }
    }

    /**
     * @return entity-specific instance of MslStore
     */
    public final MslStore getMslStore() {
        return mslStoreWrapper;
    }

   /**
    * persist MSL store
    *
    * @throws IOException
    */
    public void saveMslStore() throws IOException {
        if (mslStorePath == null) {
            appCtx.info("Not Persisting In-Memory MSL Store");
            return;
        }
        synchronized (mslStoreWrapper) {
            try {
                SharedUtil.saveToFile(mslStorePath, SharedUtil.marshalMslStore((SimpleMslStore)mslStoreWrapper.getMslStore()), true /*overwrite*/);
            } catch (MslEncodingException e) {
                throw new IOException("Error Saving MslStore file " + mslStorePath, e);
            }
            appCtx.info(String.format("MSL Store %s Updated", mslStorePath));
        }
    }


    /**
     * @return entity identity
     */
    public final String getEntityId() {
        return entityId;
    }

    /**
     * @return entity authentication data
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public final EntityAuthenticationData getEntityAuthenticationData() throws ConfigurationException, IllegalCmdArgumentException {
        return entityAuthDataHandle.getEntityAuthenticationData(appCtx, args);
    }

    /**
     * @return entity authentication factories
     */
    public final Set<EntityAuthenticationFactory> getEntityAuthenticationFactories() {
        return Collections.<EntityAuthenticationFactory>unmodifiableSet(entityAuthFactories);
    }
 
    /**
     * @return user authentication factories
     */
    public final Set<UserAuthenticationFactory> getUserAuthenticationFactories() {
        return Collections.<UserAuthenticationFactory>unmodifiableSet(userAuthFactories);
    }
 
    /**
     * @return key exchange factories
     */
    public final SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return keyxFactories;
    }

    /**
     * @param scheme key exchange scheme
     * @return wrap crypto context repository for a given key exchange scheme
     */
    public final WrapCryptoContextRepositoryHandle getWrapCryptoContextRepository(final KeyExchangeScheme scheme) {
        if (scheme == null)
            throw new IllegalArgumentException("NULL KeyExchangeScheme");
        WrapCryptoContextRepositoryHandle rep = wrapCryptoContextRepositories.get(scheme);
        if (rep == null)
             throw new IllegalArgumentException(String.format("Wrapping Key Repository nto configured for Key Exchange %s", scheme));
        return rep;
    }

    /**
     * Key exchange factory comparator. The purpose is to list key exchange schemes in order of preference.
     */
    private static class KeyExchangeFactoryComparator implements Comparator<KeyExchangeFactory> {
        /** Scheme priorities. Lower values are higher priority. */
        private final Map<KeyExchangeScheme,Integer> schemePriorities = new HashMap<KeyExchangeScheme,Integer>();

        /**
         * Create a new key exchange factory comparator.
         */
        public KeyExchangeFactoryComparator() {
            schemePriorities.put(KeyExchangeScheme.JWK_LADDER, 0);
            schemePriorities.put(KeyExchangeScheme.JWE_LADDER, 1);
            schemePriorities.put(KeyExchangeScheme.DIFFIE_HELLMAN, 2);
            schemePriorities.put(KeyExchangeScheme.SYMMETRIC_WRAPPED, 3);
            schemePriorities.put(KeyExchangeScheme.ASYMMETRIC_WRAPPED, 4);
        }

        /* (non-Javadoc)
         * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
         */
        @Override
        public int compare(KeyExchangeFactory a, KeyExchangeFactory b) {
            final KeyExchangeScheme schemeA = a.getScheme();
            final KeyExchangeScheme schemeB = b.getScheme();
            final Integer priorityA = schemePriorities.get(schemeA);
            final Integer priorityB = schemePriorities.get(schemeB);
            return priorityA.compareTo(priorityB);
        }
    }

    /**
     * Convenience method creating SortedSet of multiple key exchange factories,
     * sorted in order of preference of their use.
     * @param factories array of key exchange factories
     * @return Set of factories sorted from most to least preferable
     */
    protected static SortedSet<KeyExchangeFactory> getKeyExchangeFactorySet(KeyExchangeFactory... factories) {
        final TreeSet<KeyExchangeFactory> keyxFactoriesSet = new TreeSet<KeyExchangeFactory>(keyxFactoryComparator);
        keyxFactoriesSet.addAll(Arrays.asList(factories));
        return  Collections.unmodifiableSortedSet(keyxFactoriesSet);
    }

    /**
     * extension of WrapCryptoContextRepositoryWrapper class to intercept and report calls
     */
    private static final class AppWrapCryptoContextRepository extends WrapCryptoContextRepositoryWrapper {
        /**
         * @param appCtx application context
         * @param entityId entity identity
         * @param scheme key exchange scheme
         */
        private AppWrapCryptoContextRepository(final AppContext appCtx, final String entityId, final KeyExchangeScheme scheme) {
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

    /**
     * This is a class to serve as an interceptor to all MslStore calls.
     * It can override only the methods in MslStore the app cares about.
     * This sample implementation just prints out the information about
     * calling some selected MslStore methods.
     */
    private static final class AppMslStoreWrapper extends MslStoreWrapper {
        /**
         * @param appCtx application context
         * @param entityId entity identity
         * @param mslStore MSL store
         */
        private AppMslStoreWrapper(final AppContext appCtx, final String entityId, final MslStore mslStore) {
            super(mslStore);
            if (appCtx == null) {
                throw new IllegalArgumentException("NULL app context");
            }
            this.appCtx = appCtx;
            this.entityId = entityId;
        }

        @Override
        public long getNonReplayableId(final MasterToken masterToken) {
            final long nextId = super.getNonReplayableId(masterToken);
            appCtx.info(String.format("%s: %s - next non-replayable id %d", this, SharedUtil.getMasterTokenInfo(masterToken), nextId));
            return nextId;
        }

        @Override
        public void setCryptoContext(final MasterToken masterToken, final ICryptoContext cryptoContext) {
            if (masterToken == null) {
                appCtx.info(String.format("%s: setting crypto context with NULL MasterToken???", this));
            } else {
                appCtx.info(String.format("%s: %s %s", this,
                    (cryptoContext != null)? "Adding" : "Removing", SharedUtil.getMasterTokenInfo(masterToken)));
            }
            super.setCryptoContext(masterToken, cryptoContext);
        }

        @Override
        public void removeCryptoContext(final MasterToken masterToken) {
            appCtx.info(String.format("%s: Removing Crypto Context for %s", this, SharedUtil.getMasterTokenInfo(masterToken)));
            super.removeCryptoContext(masterToken);
        }

        @Override
        public void clearCryptoContexts() {
            appCtx.info(String.format("%s: Clear Crypto Contexts", this));
            super.clearCryptoContexts();
        }

        @Override
        public void addUserIdToken(final String userId, final UserIdToken userIdToken) throws MslException {
            appCtx.info(String.format("%s: Adding %s for userId %s", this, SharedUtil.getUserIdTokenInfo(userIdToken), userId));
            super.addUserIdToken(userId, userIdToken);
        }

        @Override
        public void removeUserIdToken(final UserIdToken userIdToken) {
            appCtx.info(String.format("%s: Removing %s", this, SharedUtil.getUserIdTokenInfo(userIdToken)));
            super.removeUserIdToken(userIdToken);
        }

        @Override
        public String toString() {
            return String.format("MslStore[%s]", entityId);
        }

        /** application context */
        private final AppContext appCtx;
        /** entity identity */
        private final String entityId;
    }
 
    /** application context */
    protected final AppContext appCtx;
    /** entity identity */
    protected final String entityId;
    /** command arguments */
    protected final CmdArguments args;
    /** MSL store */
    private final MslStoreWrapper mslStoreWrapper;
    /** MSL store file path */
    private final String mslStorePath;
    /** entity authentication data handle */
    private final AuthenticationDataHandle entityAuthDataHandle;
    /** entity authentication factories */
    private final Set<EntityAuthenticationFactory> entityAuthFactories;
    /** user authentication factories */
    private final Set<UserAuthenticationFactory> userAuthFactories;
    /** key exchange factories */
    private final SortedSet<KeyExchangeFactory> keyxFactories;
    /** wrap data repositories per key exchange */
    private final Map<KeyExchangeScheme,WrapCryptoContextRepositoryHandle> wrapCryptoContextRepositories;
    /** key exchange factory comparator for sorting key exchange factories by priority */
    private static final KeyExchangeFactoryComparator keyxFactoryComparator = new KeyExchangeFactoryComparator();
}
