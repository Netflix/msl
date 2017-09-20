/**
 * Copyright (c) 2014-2017 Netflix, Inc.  All rights reserved.
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import mslcli.common.entityauth.EntityAuthenticationHandle;
import mslcli.common.keyx.KeyExchangeHandle;
import mslcli.common.msg.MessageConfig;
import mslcli.common.userauth.UserAuthenticationHandle;
import mslcli.common.util.AppContext;
import mslcli.common.util.ConfigurationException;
import mslcli.common.util.MslStoreWrapper;
import mslcli.common.util.SharedUtil;

import com.netflix.msl.MslEncodingException;
import com.netflix.msl.MslException;
import com.netflix.msl.MslKeyExchangeException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.io.MslEncoderException;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.keyx.KeyRequestData;
import com.netflix.msl.tokens.MasterToken;
import com.netflix.msl.tokens.UserIdToken;
import com.netflix.msl.userauth.UserAuthenticationData;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.util.AuthenticationUtils;
import com.netflix.msl.util.MslStore;
import com.netflix.msl.util.SimpleMslStore;

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

        // set authutils
        this.authutils = authutils;

        // set MslStore
        if (args.getMslStorePath() != null) {
            this.mslStorePath = args.getMslStorePath().replace("{eid}", entityId);
        } else {
            this.mslStorePath = null;
        }
        this.mslStoreWrapper = new AppMslStoreWrapper(appCtx, entityId, initMslStore(appCtx, mslStorePath));
        this.eadMap = new HashMap<String,EntityAuthenticationData>();
    }

    /**
     * @return entity identity
     */
    public final String getEntityId() {
        return entityId;
    }

    @Override
    public String toString() {
        return SharedUtil.toString(this, entityId);
    }

    /**
     * validate current CmdArguments data in respect to entity, user, and key exchange handles
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public void validate() throws IllegalCmdArgumentException {
        validateEntityAuthenticationArgs();
        validateUserAuthenticationArgs();
        validateKeyExchangeArgs();
    }

    /**
     * @return message config parameters
     */
    public MessageConfig getMessageConfig() {
        // set message mslProperties
        final MessageConfig cfg = new MessageConfig();
        cfg.isEncrypted = args.isEncrypted();
        cfg.isIntegrityProtected = args.isIntegrityProtected();
        cfg.isNonReplayable = args.isNonReplayable();
        return cfg;
    }

    /**
     * @return user ID
     */

    /* ================================== ENTITY AUTHENTICATION APIs ================================================ */

    /**
     * @return entity authentication data
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public final EntityAuthenticationData getEntityAuthenticationData() throws ConfigurationException, IllegalCmdArgumentException {
        String easName = args.getEntityAuthenticationScheme();
        if (easName == null || easName.trim().length() == 0)
            throw new IllegalCmdArgumentException("Entity Authentication Scheme is not set");
        easName = easName.trim();
        for(final EntityAuthenticationHandle eah : appCtx.getEntityAuthenticationHandles()) {
            if (easName.equals(eah.getScheme().name())) {
                synchronized (eadMap) {
                    EntityAuthenticationData ead = eadMap.get(easName);
                    if (ead == null) {
                        eadMap.put(easName, ead = eah.getEntityAuthenticationData(appCtx, args));
                        appCtx.info(String.format("%s: Generated %s", this, SharedUtil.toString(ead, easName)));
                    }
                    return ead;
                }
            }
        }
        final List<String> schemes = getEntityAuthenticationSchemeNames();
        throw new IllegalCmdArgumentException(String.format("Unsupported Entity Authentication Scheme %s, Supported: %s", easName, schemes));
    }

    /**
     * @return entity authentication factories
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public final Set<EntityAuthenticationFactory> getEntityAuthenticationFactories()
        throws ConfigurationException, IllegalCmdArgumentException
    {
        final Set<EntityAuthenticationFactory> entityAuthFactories = new HashSet<EntityAuthenticationFactory>();
        for (final EntityAuthenticationHandle adh : appCtx.getEntityAuthenticationHandles()) {
            entityAuthFactories.add(adh.getEntityAuthenticationFactory(appCtx, args, authutils));
        }
        return Collections.<EntityAuthenticationFactory>unmodifiableSet(entityAuthFactories);
    }
 
    /**
     * @return registered entity authentication scheme names
     */
    private List<String> getEntityAuthenticationSchemeNames() {
        final List<String> schemes = new ArrayList<String>();
        for (final EntityAuthenticationHandle eah : appCtx.getEntityAuthenticationHandles())
            schemes.add(eah.getScheme().name());
        return schemes;
    }

    /**
     * validate entity authentication arguments
     * @throws IllegalCmdArgumentException
     */
    private void validateEntityAuthenticationArgs() throws IllegalCmdArgumentException {
        String easName = args.getEntityAuthenticationScheme();
        if (easName != null && easName.trim().length() != 0) {
            easName = easName.trim();
            final List<String> schemes = getEntityAuthenticationSchemeNames();
            if (!schemes.contains(easName))
                throw new IllegalCmdArgumentException(String.format("Unsupported Entity Authentication Scheme %s, Supported: %s", easName, schemes));
        }
    }

    /* ================================== USER AUTHENTICATION APIs ================================================ */

    /**
     * @return  user authentication data
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public UserAuthenticationData getUserAuthenticationData()
        throws ConfigurationException, IllegalCmdArgumentException
    {
        final UserAuthenticationHandle uah = getUserAuthenticationHandle();
        final UserAuthenticationData uad = uah.getUserAuthenticationData(appCtx, args, getMslStore());
        if (uad != null)
            appCtx.info(String.format("%s: Generated %s", this, SharedUtil.toString(uad, uad.getScheme())));
        return uad;
    }

    /**
     * @return current user ID
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public String getUserId()
        throws ConfigurationException, IllegalCmdArgumentException
    {
        final UserAuthenticationHandle uah = getUserAuthenticationHandle();
        return uah.getUserId(appCtx, args);
    }

    /**
     * @return UserAuthenticationHandle for a given user authentication scheme
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    private UserAuthenticationHandle getUserAuthenticationHandle()
        throws ConfigurationException, IllegalCmdArgumentException
    {
        final String uasName = args.getUserAuthenticationScheme();
        if (uasName == null || uasName.trim().length() == 0)
            throw new IllegalCmdArgumentException("User Authentication Scheme is not set");
        for (final UserAuthenticationHandle uah : appCtx.getUserAuthenticationHandles()) {
            if (uah.getScheme().name().equals(uasName)) {
                return uah;
            }
        }
        // UserAuthenticationHandle not found. Generate helpful exception 
        final List<String> schemes = getUserAuthenticationSchemeNames();
        throw new IllegalCmdArgumentException(String.format("Unsupported User Authentication Scheme %s, Supported: %s", uasName, schemes));
    }

    /**
     * @return user authentication factories
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public final Set<UserAuthenticationFactory> getUserAuthenticationFactories()
        throws ConfigurationException, IllegalCmdArgumentException
    {
        final Set<UserAuthenticationFactory> userAuthFactories = new HashSet<UserAuthenticationFactory>();
        for (final UserAuthenticationHandle uah : appCtx.getUserAuthenticationHandles()) {
            userAuthFactories.add(uah.getUserAuthenticationFactory(appCtx, args, authutils));
        }
        return Collections.<UserAuthenticationFactory>unmodifiableSet(userAuthFactories);
    }
 
    /**
     * @return registered user authentication scheme names
     */
    private List<String> getUserAuthenticationSchemeNames() {
        final List<String> schemes = new ArrayList<String>();
        for (final UserAuthenticationHandle uah : appCtx.getUserAuthenticationHandles())
            schemes.add(uah.getScheme().name());
        return schemes;
    }

    /**
     * validate user authentication arguments
     * @throws IllegalCmdArgumentException
     */
    private void validateUserAuthenticationArgs() throws IllegalCmdArgumentException {
        String uasName = args.getUserAuthenticationScheme();
        if (uasName != null && uasName.trim().length() != 0) {
            uasName = uasName.trim();
            final List<String> schemes = getUserAuthenticationSchemeNames();
            if (!schemes.contains(uasName))
                throw new IllegalCmdArgumentException(String.format("Unsupported User Authentication Scheme %s, Supported: %s", uasName, schemes));
        }
    }

    /* ================================== KEY EXCHANGE APIs ================================================ */

    /**
     * @return key request data
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     * @throws MslKeyExchangeException
     */
    public KeyRequestData getKeyRequestData()
        throws ConfigurationException, IllegalCmdArgumentException, MslKeyExchangeException
    {
        final String kxsName = args.getKeyExchangeScheme();
        if (kxsName == null || kxsName.trim().isEmpty()) {
            throw new IllegalCmdArgumentException("NULL Key Exchange Type");
        }
        final String kxmName = args.getKeyExchangeMechanism();

        for (final KeyExchangeHandle kxh : appCtx.getKeyExchangeHandles()) {
            if (kxh.getScheme().name().equals(kxsName)) {
                final KeyRequestData krd =  kxh.getKeyRequestData(appCtx, args);
                appCtx.info(String.format("%s: Generated %s", this, SharedUtil.toString(krd, krd.getKeyExchangeScheme(), kxmName)));
                return krd;
            }
        }
        final List<String> schemes = getKeyExchangeSchemeNames();
        throw new IllegalCmdArgumentException(String.format("Unsupported Key Exchange Scheme %s, Supported: %s", kxsName, schemes));
    }

    /**
     * @return key exchange factories
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    public final SortedSet<KeyExchangeFactory> getKeyExchangeFactories()
        throws ConfigurationException, IllegalCmdArgumentException
    {
        // key exchange handles
        final List<KeyExchangeFactory> keyxFactoriesList = new ArrayList<KeyExchangeFactory>();
        final List<KeyExchangeHandle> keyxHandles = appCtx.getKeyExchangeHandles();
        for (final KeyExchangeHandle kxh : keyxHandles) {
            keyxFactoriesList.add(kxh.getKeyExchangeFactory(appCtx, args, authutils));
        }
        final KeyExchangeFactoryComparator keyxFactoryComparator = new KeyExchangeFactoryComparator(keyxFactoriesList);
        final TreeSet<KeyExchangeFactory> keyxFactoriesSet = new TreeSet<KeyExchangeFactory>(keyxFactoryComparator);
        keyxFactoriesSet.addAll(keyxFactoriesList);
        return  Collections.unmodifiableSortedSet(keyxFactoriesSet);
    }

    /**
     * @return registered user authentication scheme names
     */
    private List<String> getKeyExchangeSchemeNames() {
        final List<String> schemes = new ArrayList<String>();
        for (final KeyExchangeHandle kxh : appCtx.getKeyExchangeHandles())
            schemes.add(kxh.getScheme().name());
        return schemes;
    }

    /**
     * validate key exchange arguments
     * @throws IllegalCmdArgumentException
     */
    private void validateKeyExchangeArgs() throws IllegalCmdArgumentException {
        String kxsName = args.getKeyExchangeScheme();
        if (kxsName != null && kxsName.trim().length() != 0) {
            kxsName = kxsName.trim();
            final List<String> schemes = getKeyExchangeSchemeNames();
            if (!schemes.contains(kxsName))
                throw new IllegalCmdArgumentException(String.format("Unsupported Key Exchange Scheme %s, Supported: %s", kxsName, schemes));
        }
    }

    /**
     * Key exchange factory comparator. The purpose is to list key exchange schemes in order of preference.
     */
    private static class KeyExchangeFactoryComparator implements Comparator<KeyExchangeFactory> {
        /** Scheme priorities. Lower values are higher priority. */
        private final Map<KeyExchangeScheme,Integer> schemePriorities = new HashMap<KeyExchangeScheme,Integer>();

        /**
         * Create a new key exchange factory comparator.
         * @param factories factories in order of their preference
         */
        public KeyExchangeFactoryComparator(final List<KeyExchangeFactory> factories) {
            int priority = 0;
            for (final KeyExchangeFactory f : factories) {
                schemePriorities.put(f.getScheme(), priority++);
            }
        }

        /* (non-Javadoc)
         * @see java.util.Comparator#compare(java.lang.Object, java.lang.Object)
         */
        @Override
        public int compare(final KeyExchangeFactory a, final KeyExchangeFactory b) {
            final KeyExchangeScheme schemeA = a.getScheme();
            final KeyExchangeScheme schemeB = b.getScheme();
            final Integer priorityA = schemePriorities.get(schemeA);
            final Integer priorityB = schemePriorities.get(schemeB);
            return priorityA.compareTo(priorityB);
        }
    }

   /* ================================== MSL STORE APIs ================================================ */

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
            appCtx.info(String.format("%s: Not Persisting In-Memory MSL Store", this));
            return;
        }
        synchronized (mslStoreWrapper) {
            try {
                SharedUtil.saveToFile(mslStorePath, SharedUtil.marshalMslStore((SimpleMslStore)mslStoreWrapper.getMslStore()), true /*overwrite*/);
            } catch (final MslEncodingException e) {
                throw new IOException("Error Saving MslStore file " + mslStorePath, e);
            } catch (final MslEncoderException e) {
                throw new IOException("Error Saving MslStore file " + mslStorePath, e);
            }
            appCtx.info(String.format("%s: MSL Store %s Updated", this, mslStorePath));
        }
    }

    /**
     * Initialize MslStore
     *
     * @param appCtx application context
     * @param mslStorePath MSL store path
     * @return MSL store
     * @throws ConfigurationException
     */
    private static SimpleMslStore initMslStore(final AppContext appCtx, final String mslStorePath)
        throws ConfigurationException
    {
        if (mslStorePath == null) {
            appCtx.info("Creating Non-Persistent MSL Store");
            return new SimpleMslStore();
        } else if (SharedUtil.isExistingFile(mslStorePath)) {
            appCtx.info("Loading Existing MSL Store " + mslStorePath);
            try {
                return (SimpleMslStore)SharedUtil.unmarshalMslStore(SharedUtil.readFromFile(mslStorePath));
            } catch (final Exception e) {
                throw new ConfigurationException("Error Loading MSL Store " + mslStorePath, e);
            }
        } else if (SharedUtil.isValidNewFile(mslStorePath)) {
            appCtx.info("Creating New MSL Store " + mslStorePath);
            return new SimpleMslStore();
        } else {
            throw new IllegalArgumentException("MSL Store: Invalid File Path: " + mslStorePath);
        }
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
            return String.format("%s{%s}", super.toString(), entityId);
        }

        /** application context */
        private final AppContext appCtx;
        /** entity identity */
        private final String entityId;
    }
 
   /* ================================== INSTANCE VARIABLES ================================================ */

    /** application context */
    protected final AppContext appCtx;
    /** entity identity */
    protected final String entityId;
    /** command arguments */
    protected final CmdArguments args;
    /** authentication utilities */
    protected final AuthenticationUtils authutils;
    /** MSL store */
    private final MslStoreWrapper mslStoreWrapper;
    /** MSL store file path */
    private final String mslStorePath;
    /** entity authentication data per scheme */
    private final Map<String,EntityAuthenticationData> eadMap;
}
