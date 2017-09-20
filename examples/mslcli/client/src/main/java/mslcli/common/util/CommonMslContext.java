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

package mslcli.common.util;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;

import com.netflix.msl.MslConstants.CompressionAlgorithm;
import com.netflix.msl.MslCryptoException;
import com.netflix.msl.crypto.ICryptoContext;
import com.netflix.msl.entityauth.EntityAuthenticationData;
import com.netflix.msl.entityauth.EntityAuthenticationFactory;
import com.netflix.msl.entityauth.EntityAuthenticationScheme;
import com.netflix.msl.io.DefaultMslEncoderFactory;
import com.netflix.msl.io.MslEncoderFactory;
import com.netflix.msl.io.MslEncoderFormat;
import com.netflix.msl.keyx.KeyExchangeFactory;
import com.netflix.msl.keyx.KeyExchangeScheme;
import com.netflix.msl.msg.MessageCapabilities;
import com.netflix.msl.tokens.TokenFactory;
import com.netflix.msl.userauth.UserAuthenticationFactory;
import com.netflix.msl.userauth.UserAuthenticationScheme;
import com.netflix.msl.util.MslContext;
import com.netflix.msl.util.MslStore;

import mslcli.common.IllegalCmdArgumentException;
import mslcli.common.MslConfig;

/**
 * <p>ABstract class for MSL context specific to the given entity.</p>
 * 
 * @author Vadim Spector <vspector@netflix.com>
 */

public abstract class CommonMslContext extends MslContext {
    /**
     * <p>Create a new MSL context.</p>
     * 
     * @param appCtx application context
     * @param mslCfg MSL configuration.
     * @throws ConfigurationException
     * @throws IllegalCmdArgumentException
     */
    protected CommonMslContext(final AppContext appCtx, final MslConfig mslCfg) throws ConfigurationException, IllegalCmdArgumentException {
        if (appCtx == null) {
            throw new IllegalArgumentException("NULL app context");
        }
        if (mslCfg == null) {
            throw new IllegalArgumentException("NULL MSL config");
        }

        // Initialize MSL config.
        this.mslCfg = mslCfg;
        
        // Entity authentication data.
        this.entityAuthData = mslCfg.getEntityAuthenticationData();

        // Message capabilities.
        final Set<CompressionAlgorithm> compressionAlgos = new HashSet<CompressionAlgorithm>(Arrays.asList(CompressionAlgorithm.GZIP, CompressionAlgorithm.LZW));
        final List<String> languages = Arrays.asList("en-US");
        final Set<MslEncoderFormat> encoderFormats = new HashSet<MslEncoderFormat>(Arrays.asList(MslEncoderFormat.JSON));
        this.messageCaps = new MessageCapabilities(compressionAlgos, languages, encoderFormats);
        
        // Entity authentication factories.
        this.entityAuthFactories = mslCfg.getEntityAuthenticationFactories();
        
        // User authentication factories.
        this.userAuthFactories = mslCfg.getUserAuthenticationFactories();
        
        // Key exchange factories.
        this.keyxFactories = mslCfg.getKeyExchangeFactories();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getTime()
     */
    @Override
    public final long getTime() {
        return System.currentTimeMillis();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getRandom()
     */
    @Override
    public final Random getRandom() {
        return new SecureRandom();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#isPeerToPeer()
     */
    @Override
    public final boolean isPeerToPeer() {
        return false;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMessageCapabilities()
     */
    @Override
    public final MessageCapabilities getMessageCapabilities() {
        return messageCaps;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationData(com.netflix.msl.util.MslContext.ReauthCode)
     */
    @Override
    public final EntityAuthenticationData getEntityAuthenticationData(final ReauthCode reauthCode) {
        return entityAuthData;
    }
    
    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslCryptoContext()
     */
    @Override
    public abstract ICryptoContext getMslCryptoContext() throws MslCryptoException;

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationFactory(com.netflix.msl.entityauth.EntityAuthenticationScheme)
     */
    @Override
    public final EntityAuthenticationFactory getEntityAuthenticationFactory(final EntityAuthenticationScheme scheme) {
        for (final EntityAuthenticationFactory factory : entityAuthFactories) {
            if (factory.getScheme().equals(scheme))
                return factory;
        }
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationFactory(com.netflix.msl.userauth.UserAuthenticationScheme)
     */
    @Override
    public final UserAuthenticationFactory getUserAuthenticationFactory(final UserAuthenticationScheme scheme) {
       for (final UserAuthenticationFactory factory : userAuthFactories) {
            if (factory.getScheme().equals(scheme))
                return factory;
        }
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getTokenFactory()
     */
    @Override
    public abstract TokenFactory getTokenFactory();

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactory(com.netflix.msl.keyx.KeyExchangeScheme)
     */
    @Override
    public final KeyExchangeFactory getKeyExchangeFactory(final KeyExchangeScheme scheme) {
        for (final KeyExchangeFactory factory : keyxFactories) {
            if (factory.getScheme().equals(scheme))
                return factory;
        }
        return null;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeFactories()
     */
    @Override
    public final SortedSet<KeyExchangeFactory> getKeyExchangeFactories() {
        return keyxFactories;
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getEntityAuthenticationScheme()
     */
    @Override
    public final EntityAuthenticationScheme getEntityAuthenticationScheme(final String name) {
        return EntityAuthenticationScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getKeyExchangeScheme()
     */
    @Override
    public final KeyExchangeScheme getKeyExchangeScheme(final String name) {
        return KeyExchangeScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getUserAuthenticationScheme()
     */
    @Override
    public final UserAuthenticationScheme getUserAuthenticationScheme(final String name) {
        return UserAuthenticationScheme.getScheme(name);
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslStore()
     */
    @Override
    public final MslStore getMslStore() {
        return mslCfg.getMslStore();
    }

    /* (non-Javadoc)
     * @see com.netflix.msl.util.MslContext#getMslEncoderFactory()
     */
    @Override
    public MslEncoderFactory getMslEncoderFactory() {
        return encoderFactory;
    }

    @Override
    public final String toString() {
        return SharedUtil.toString(this);
    }

    /** MSL config */
    private final MslConfig mslCfg;
    /** Entity authentication data. */
    private final EntityAuthenticationData entityAuthData;
    /** message capabilities */
    private final MessageCapabilities messageCaps;
    /** entity authentication factories */
    private final Set<EntityAuthenticationFactory> entityAuthFactories;
    /** user authentication factories */
    private final Set<UserAuthenticationFactory> userAuthFactories;
    /** key exchange factories */
    private final SortedSet<KeyExchangeFactory> keyxFactories;
    /** MSL encoder factory. */
    private final MslEncoderFactory encoderFactory = new DefaultMslEncoderFactory();
}
